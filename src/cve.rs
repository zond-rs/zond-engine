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
//!
//! Every finding records the CPEs it was drawn from, as
//! [`Finding::cpes`]. The claim rests on those identifications, and a
//! [`merge`](crate::merge) that folds in a newer scan identifying another
//! version has to be able to tell which findings went with the old one.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::io::BufRead;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::model::confidence::Confidence;
use crate::model::finding::{
    DetectionClass, DetectionId, Excerpt, Finding, Reference, Severity, Version,
};
use crate::model::host::Host;
use crate::model::port::{Build, Protocol, Service};
use crate::record::wire;
use crate::report::ScanReport;
use crate::version::version_cmp;

pub(crate) mod advisories;
mod applicability;
mod backport;
pub(crate) mod packages;

use advisories::OpenKind;
pub use advisories::{Advisories, AdvisoriesError};
use applicability::Applies;
use backport::{Placement, Ruling, Unplaced, Unsettled, Vulnerable, Withdrawal};

/// The reserved identity the engine's built-in correlator stamps on every finding
/// it produces, so a report can say exactly what concluded a vulnerability. A
/// third-party detection may not claim the `zond:` namespace.
const CORRELATOR_ID: &str = "zond:cve-kev";

/// The prefix a catalogue read from outside this crate may not claim.
const RESERVED_PREFIX: &str = "zond:";

/// The shipped catalogue's version, carried on every finding it produces.
///
/// It versions the verdicts as well as the data, since a finding is both, and
/// moves whenever either does: a report drawn from one is distinguishable from
/// a report drawn from another by it, which is the whole reason a dataset
/// carries a version, and a [`merge`](crate::merge) retires an earlier
/// correlator's claims wherever a later one judged the same port. `0.3.0`
/// marks the correlator that tells a distribution's build from the upstream
/// release it started from and keys each claim on what it is about, over a
/// converted feed whose entries carry a CPE's patch level as part of the
/// release they name and leave out ranges NVD states only for one platform,
/// beside the hand-picked entries in `seed.toml`.
const SEED_VERSION: Version = Version::new(0, 3, 0);

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

/// The longest a catalogue entry's own title may be and still be used as a
/// finding's summary.
///
/// A summary sits in a column beside a port and a severity, and the rows around
/// it are phrases: `squid 6.13 has 7 known vulnerabilities`, `VNC offered the
/// None security type`. Every hand-written entry in the shipped seed is under
/// sixty characters. Anything longer is a description that was cut to fit rather
/// than a title somebody wrote, and it belongs in the excerpt.
const MAX_SUMMARY_BYTES: usize = 80;

/// Correlates a finished host's services against the shipped catalogue,
/// recording findings on each port whose software an entry matches.
///
/// Reads each port's service CPE, matches vendor, product and version against
/// the dataset, and hands each match back to the port it concerns. Replaces
/// what the same catalogue drew on the port before, so a re-run reaches the
/// same findings rather than doubling them.
///
/// With no distributor's data, a distribution's build is judged only as far as
/// its upstream version goes, and said to be; [`Correlator`] takes the data.
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
    Correlator::new(catalogue).correlate(host);
}

/// A correlation to run: a catalogue of known vulnerabilities, and the
/// distributors' own data a distribution's build is judged against.
///
/// The catalogue says which vulnerabilities an upstream release has. A
/// distribution's build of that release is a different question, because the
/// distributor patches the release it ships without moving its version, and
/// only the distributor's data answers it: which of those vulnerabilities its
/// build fixed, from which package version, and which never affected it. With
/// that data a service naming its build (`OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13`)
/// is reported for what the build still carries, with the build to install;
/// without it, the same service is reported for its upstream release's
/// vulnerabilities at a confidence that says the build was not checked.
///
/// ```
/// use zond_engine::cve::{Catalogue, Correlator};
/// use zond_engine::model::host::Host;
/// # fn advisories() -> Vec<zond_engine::cve::Advisories> { Vec::new() }
///
/// let advisories = advisories(); // read from a cache, see `Advisories::from_bytes`
/// let mut host = Host::new("192.0.2.1".parse().unwrap());
/// Correlator::new(Catalogue::embedded())
///     .with_advisories(&advisories)
///     .correlate(&mut host);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Correlator<'a> {
    catalogue: &'a Catalogue,
    advisories: &'a [Advisories],
}

impl<'a> Correlator<'a> {
    /// A correlation against `catalogue` and no distributor's data.
    pub fn new(catalogue: &'a Catalogue) -> Self {
        Self {
            catalogue,
            advisories: &[],
        }
    }

    /// Judges a distribution's build against its distributor's data, one
    /// [`Advisories`] per distributor. Where two name the same distributor,
    /// the first is used.
    pub fn with_advisories(mut self, advisories: &'a [Advisories]) -> Self {
        self.advisories = advisories;
        self
    }

    /// Records on `host`'s ports what this correlation draws, replacing what
    /// the same catalogue drew there before.
    pub fn correlate(&self, host: &mut Host) {
        // Collect first, mutate second: the read borrows the host's ports and
        // the write needs them mutably, so the two cannot overlap.
        for judged in self.judgements(host) {
            host.replace_port_correlations(
                judged.number,
                judged.protocol,
                self.catalogue.id(),
                judged.findings,
            );
        }
    }

    /// [`correlate`](Self::correlate), over every host in a finished report.
    pub fn correlate_report(&self, report: &mut ScanReport) {
        for host in report.hosts_mut() {
            self.correlate(host);
        }
    }

    /// What [`correlate`](Self::correlate) would record on `host`, port by
    /// port, without recording it.
    ///
    /// For a scan correlating in place, which reads first and writes only a
    /// host whose correlations change: a write is announced to whoever watches
    /// the scan and taken down by its journal, and most hosts match nothing. A
    /// port is listed where the catalogue draws something on it or drew
    /// something there before, since a correlation is replaced whole and one
    /// that now draws nothing withdraws what the last one drew.
    pub(crate) fn judgements(&self, host: &Host) -> Vec<PortJudgement> {
        host.ports()
            .filter_map(|port| {
                let service = port.service()?;
                let mut findings = Vec::new();
                let mut withdrawn = Withdrawn::default();
                for judged in service
                    .cpes()
                    .iter()
                    .filter_map(|cpe| Judged::of(service, cpe))
                {
                    let judgement = self.catalogue.judge(&judged, self.advisories);
                    findings.extend(judgement.findings);
                    withdrawn.add(judgement.withdrawn);
                }
                let held = port.findings().any(|finding| {
                    finding.is_correlation() && finding.detection().id() == self.catalogue.id()
                });
                (!findings.is_empty() || held || withdrawn.total() > 0).then(|| PortJudgement {
                    number: port.number(),
                    protocol: port.protocol(),
                    findings,
                    withdrawn,
                })
            })
            .collect()
    }
}

/// One port's correlations against one catalogue, computed and not yet
/// recorded.
pub(crate) struct PortJudgement {
    /// The port's number.
    pub(crate) number: u16,
    /// Its transport.
    pub(crate) protocol: Protocol,
    /// Every finding the catalogue draws on it, which replaces whatever the
    /// same catalogue drew there before. Empty where it draws none on a port
    /// that held some.
    pub(crate) findings: Vec<Finding>,
    /// What matched and was not reported, by why.
    pub(crate) withdrawn: Withdrawn,
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
    Correlator::new(catalogue).correlate_report(report);
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
            // With the options `build.rs` wrote it with: variable-width integers.
            use bincode::Options as _;
            let (pool, vulnerability) = bincode::options()
                .deserialize(EMBEDDED_DB)
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

    /// Every finding this catalogue has for a service CPE, judged as an
    /// upstream release named by the CPE alone.
    #[cfg(test)]
    fn findings_for(&self, cpe: &str) -> Vec<Finding> {
        Judged::upstream(cpe)
            .map(|judged| self.judge(&judged, &[]).findings)
            .unwrap_or_default()
    }

    /// Every finding this catalogue draws on one identification of a service,
    /// and what it withdrew.
    ///
    /// The entries naming the software at the version found, grouped by what
    /// can honestly be said about each, one finding per group. What can be
    /// said depends on more than the version: whether the entry constrained
    /// the version at all, where the flaw lives, and whose build the service
    /// is, which for a distribution's build means what the distributor's own
    /// data in `advisories` says. See [`Verdict`].
    fn judge(&self, judged: &Judged<'_>, advisories: &[Advisories]) -> Judgement {
        let mut matched: Vec<Vulnerability<'_>> = self
            .vulnerability
            .iter()
            .map(|entry| self.view(entry))
            .filter(|vulnerability| vulnerability.matches(&judged.parsed))
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

        // Placed once for the identification, and only where anything matched:
        // most services match nothing and have nothing to place.
        let placement = match (judged.build, matched.is_empty()) {
            (Some(build), false) => Some(Placement::of(
                build,
                &judged.vendor_product(),
                &judged.parsed.version,
                advisories,
            )),
            _ => None,
        };

        // Grouped before summarising, because the groups are different claims
        // and a summary may not average them. The map keeps the sorted order
        // within each group. What does not apply is withdrawn here and only
        // counted.
        let mut groups: BTreeMap<Verdict, Vec<Ruled<'_>>> = BTreeMap::new();
        let mut withdrawn = Withdrawn::default();
        for vulnerability in matched {
            match Verdict::of(&vulnerability, judged, placement.as_ref()) {
                Classified::Withdrawn(why) => withdrawn.count(why),
                Classified::Grouped(verdict, ruling) => {
                    groups.entry(verdict).or_default().push(Ruled {
                        vulnerability,
                        ruling,
                    })
                }
            }
        }

        let context = Context {
            judged,
            placement: placement.as_ref().and_then(|placed| placed.as_ref().ok()),
            unplaced: placement.as_ref().and_then(|placed| placed.as_ref().err()),
        };

        // Said once, on the first finding, so a reader who counts the
        // identifiers the catalogue holds for this release can reconcile them
        // with what is reported.
        let mut note = withdrawn.describe(&context);
        let findings = groups
            .into_iter()
            .filter_map(|(verdict, entries)| {
                self.finding(&context, verdict, &entries, note.take().as_deref())
            })
            .collect();
        Judgement {
            findings,
            withdrawn,
        }
    }

    /// The one finding a group of matches produces.
    ///
    /// A version-matched CPE against a real feed draws dozens: Apache 2.4.49 has
    /// sixty-eight, MySQL 8.0.32 a hundred and eighteen. Recorded one by one they
    /// are not a report, they are a wall, and they push past
    /// [`MAX_FINDINGS_PER_SUBJECT`](crate::model::finding::MAX_FINDINGS_PER_SUBJECT)
    /// on a host running a handful of identifiable services, at which point the
    /// ones that survive are decided by arrival order rather than by severity.
    ///
    /// So a group arrives as one finding that says how many and how bad,
    /// carrying every one of them as references, worst first. A reader
    /// scanning a port table sees one row per kind of claim about the service;
    /// a reader with the report open has the identifiers.
    ///
    /// `note` is a sentence about the identification as a whole, appended to
    /// the excerpt.
    fn finding(
        &self,
        context: &Context<'_, '_>,
        verdict: Verdict,
        entries: &[Ruled<'_>],
        note: Option<&str>,
    ) -> Option<Finding> {
        let judged = context.judged;
        let worst = &entries.first()?.vulnerability;
        let severity = wire::severity(worst.severity)?;
        let detection =
            DetectionId::new(self.id.clone(), self.version, self.content_hash.clone()).ok()?;
        let cpe = judged.cpe;

        // Named the way the port table names it: the service's own product
        // name where the identification carried one (`Apache HTTP Server
        // 2.4.7`, not `http_server 2.4.7`), and the catalogue's where it did
        // not. The vendor is in the CPE the excerpt quotes, for anyone who
        // needs to tell two products of the same name apart.
        let product = judged.product.unwrap_or(worst.product);
        let software = match judged.parsed.version.is_empty() {
            true => product.to_string(),
            false => format!("{product} {}", judged.parsed.version),
        };

        let count = entries.len();
        let counted = |wanted: Severity| {
            entries
                .iter()
                .filter(|entry| wire::severity(entry.vulnerability.severity) == Some(wanted))
                .count()
        };
        let (critical, high) = (counted(Severity::Critical), counted(Severity::High));
        let named: Vec<&str> = entries
            .iter()
            .take(MAX_NAMED_IN_EXCERPT)
            .map(|entry| entry.vulnerability.cve)
            .collect();
        let named = named.join(", ");
        let only = (count == 1).then_some(worst);
        let cves = |one: &str, many: &str| match count {
            1 => format!("1 {one}"),
            n => format!("{n} {many}"),
        };
        let tally = format!("{critical} critical and {high} high");
        let known = match count {
            1 => "1 known vulnerability".to_string(),
            n => format!("{n} known vulnerabilities"),
        };
        let distributor = context.distributor_label();
        let placed = context.placed_as();

        let (title, excerpt) = match verdict {
            Verdict::Affected | Verdict::AnyVersion => {
                let checked = verdict == Verdict::Affected;
                let excerpt = match (only, checked) {
                    (Some(entry), true) => format!(
                        "{cpe} matches {} {} {}",
                        entry.vendor, entry.product, entry.affected
                    ),
                    (Some(entry), false) => format!(
                        "{cpe} is {} {}, which this entry names at any version: \
                         the version found was not checked against anything",
                        entry.vendor, entry.product
                    ),
                    (None, true) => {
                        format!("{cpe} matches {known}, {tally}. The worst are {named}")
                    }
                    (None, false) => format!(
                        "{cpe} matches {count} entries naming this software at any version: \
                         the version found was not checked against anything. They include {named}"
                    ),
                };
                match only {
                    // One match is its own best description, where the entry
                    // has a title short enough to be one. NVD publishes no
                    // title, and `import::nvd` cuts the description to fit, so
                    // almost every NVD entry's is a paragraph cut mid-word;
                    // that moves to the excerpt, where it is the evidence
                    // anyway, and the line says what it says for a run.
                    Some(entry) if entry.title.len() <= MAX_SUMMARY_BYTES => {
                        (entry.title.to_string(), excerpt)
                    }
                    Some(entry) => (
                        format!("{software} has 1 known vulnerability"),
                        format!("{excerpt}. {}", entry.title),
                    ),
                    None => (
                        format!("{software} has {count} known vulnerabilities"),
                        excerpt,
                    ),
                }
            }
            Verdict::BuildUnchecked => {
                let build = judged.build?;
                let why = context
                    .unplaced
                    .map(|unplaced| unplaced.describe(distributor))
                    .unwrap_or_else(|| format!("no {distributor} advisory data was loaded"));
                (
                    format!(
                        "{software}: {}, build unchecked",
                        cves("upstream CVE", "upstream CVEs")
                    ),
                    format!(
                        "{cpe} matches {known} in the upstream release, {tally}. \
                         {distributor} backports fixes without changing the upstream \
                         version, and whether this build ({}) still carries them was not \
                         checked: {why}. The worst are {named}",
                        build.describe()
                    ),
                )
            }
            Verdict::FixAvailable => (
                format!(
                    "{software}: {} in a newer {distributor} build",
                    cves("CVE fixed", "CVEs fixed")
                ),
                format!(
                    "{placed} predates the builds that fixed {known}, {tally}, by \
                     {distributor}'s own data. The worst are {named}"
                ),
            ),
            Verdict::EsmOnly => (
                format!(
                    "{software}: {} only in Ubuntu Pro",
                    cves("CVE fixed", "CVEs fixed")
                ),
                format!(
                    "{placed} carries {known}, {tally}, fixed by Ubuntu only in its \
                     Expanded Security Maintenance pockets, which a machine receives with an \
                     Ubuntu Pro subscription. The build this host runs is not one of those. \
                     The worst are {named}"
                ),
            ),
            Verdict::NoFix => (
                format!(
                    "{software}: {} for {distributor} {}",
                    cves("CVE with no fix", "CVEs with no fix"),
                    context.release()
                ),
                format!(
                    "{placed} carries {known}, {tally}, not fixed by {distributor} in this \
                     release{}. The worst are {named}",
                    open_kinds(entries)
                ),
            ),
            Verdict::NeedsSetting => {
                let mut settings: Vec<&str> = Vec::new();
                for entry in entries {
                    if let Some(requires) = entry.vulnerability.requires()
                        && !settings.contains(&requires)
                    {
                        settings.push(requires);
                    }
                }
                let shown = settings
                    .iter()
                    .take(MAX_NAMED_IN_EXCERPT)
                    .copied()
                    .collect::<Vec<_>>()
                    .join("; ");
                let more = match settings.len().saturating_sub(MAX_NAMED_IN_EXCERPT) {
                    0 => String::new(),
                    n => format!(" and {n} more"),
                };
                (
                    format!(
                        "{software}: {} a non-default setting",
                        cves("CVE needs", "CVEs need")
                    ),
                    format!(
                        "{cpe} matches {known}, {tally}, reaching the service only where it \
                         is set up in a way it is not by default: {shown}{more}. The worst are \
                         {named}"
                    ),
                )
            }
            Verdict::PatchLevelHidden => (
                format!(
                    "{software}: {}, patch level not visible",
                    cves("CVE", "CVEs")
                ),
                format!(
                    "{distributor} has fixed {known}, {tally}, in builds of {} for release \
                     {}, and the banner does not say which build this is: it may predate the \
                     fixes or carry them. The worst are {named}",
                    context.package(),
                    context.release()
                ),
            ),
            Verdict::Untriaged => (
                format!(
                    "{software}: {} not triaged by {distributor}",
                    cves("CVE", "CVEs")
                ),
                format!(
                    "{placed} matches {known} in the upstream release, {tally}, not yet \
                     judged for this release in {distributor}'s data, or not recorded there. \
                     The worst are {named}"
                ),
            ),
        };
        let excerpt = [
            Some(excerpt),
            priorities(context, entries),
            note.map(str::to_owned),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(". ");

        let mut finding = Finding::new(
            detection,
            title,
            severity,
            verdict.confidence(),
            DetectionClass::Passive,
        )
        .ok()?
        .with_excerpt(Excerpt::new(excerpt))
        .with_cpe(cpe)
        .with_subject(context.subject(verdict));
        if let Some(build) = judged.build {
            finding = finding.with_build(build.clone());
        }
        if let Some(placement) = context.placement
            && let Ok(stamp) = DetectionId::new(
                placement.advisories.id(),
                placement.advisories.version(),
                placement.advisories.content_hash(),
            )
        {
            finding = finding.with_advised_by(stamp);
        }

        // Every one of them, because this is the record: a summary that says
        // forty-four and cites twenty is a report a reader cannot reconcile, and
        // the presentation is the right place to decide how many of them fit on
        // a line. The severity sort above still decides the order, so a front
        // end showing the first few shows the worst few.
        for entry in entries {
            if let Some(reference) = Reference::cve(entry.vulnerability.cve) {
                finding = finding.with_reference(reference);
            }
        }

        // A weakness and a remedy describe one vulnerability. On a summary they
        // would be the worst entry's, printed beside a count of dozens as if
        // they characterised all of them.
        if let Some(entry) = only {
            if let Some(cwe) = entry.cwe {
                finding = finding.with_reference(Reference::cwe(cwe));
            }
            if let Some(remediation) = entry.remediation {
                finding = finding.with_remediation(remediation);
            }
        }
        if let Some(remediation) = remediation(context, verdict, entries) {
            finding = finding.with_remediation(remediation);
        }
        Some(finding)
    }
}

/// One identification's findings, and what was withdrawn from it.
pub(crate) struct Judgement {
    /// One finding per kind of claim.
    pub(crate) findings: Vec<Finding>,
    /// What matched and was not reported, by why.
    pub(crate) withdrawn: Withdrawn,
}

/// Known vulnerabilities of a release that a correlation did not report, by
/// why not.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Withdrawn {
    /// Fixed at or below the build the service runs, by the distributor's
    /// data.
    pub(crate) fixed: usize,
    /// Never carried by the release, by the distributor's data.
    pub(crate) not_affected: usize,
    /// In the client programs installed beside the service, or needing an
    /// account on the host.
    pub(crate) elsewhere: usize,
}

impl Withdrawn {
    /// Counts one more.
    fn count(&mut self, why: Why) {
        match why {
            Why::Fixed => self.fixed += 1,
            Why::NotAffected => self.not_affected += 1,
            Why::Elsewhere => self.elsewhere += 1,
        }
    }

    /// How many in all.
    pub(crate) fn total(&self) -> usize {
        self.fixed + self.not_affected + self.elsewhere
    }

    /// Adds another identification's.
    pub(crate) fn add(&mut self, other: Withdrawn) {
        self.fixed += other.fixed;
        self.not_affected += other.not_affected;
        self.elsewhere += other.elsewhere;
    }

    /// The sentence an excerpt carries about them, or [`None`] where there
    /// are none.
    fn describe(&self, context: &Context<'_, '_>) -> Option<String> {
        if self.total() == 0 {
            return None;
        }
        let distributor = context.distributor_label();
        let mut parts = Vec::new();
        let are = |count: usize| match count {
            1 => "is",
            _ => "are",
        };
        if self.fixed > 0 {
            parts.push(format!(
                "{} {} fixed in this build",
                self.fixed,
                are(self.fixed)
            ));
        }
        if self.not_affected > 0 {
            parts.push(format!(
                "{} never affected {distributor} {}",
                self.not_affected,
                context.release()
            ));
        }
        let by_data = (!parts.is_empty()).then(|| {
            format!(
                "Of this release's other known vulnerabilities, {}, by {distributor}'s own data",
                parts.join(" and ")
            )
        });
        let elsewhere = (self.elsewhere > 0).then(|| {
            format!(
                "{} more {} in its client programs or {} an account on the host",
                self.elsewhere,
                match self.elsewhere {
                    1 => "lives",
                    _ => "live",
                },
                match self.elsewhere {
                    1 => "needs",
                    _ => "need",
                }
            )
        });
        let sentence = [by_data, elsewhere]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("; ");
        Some(format!("{sentence}. None of these is reported"))
    }
}

/// Why one vulnerability was withdrawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Why {
    Fixed,
    NotAffected,
    Elsewhere,
}

/// Where a matched vulnerability goes.
enum Classified {
    /// Not reported, for this reason.
    Withdrawn(Why),
    /// Reported in this group, with what the distributor's data said where it
    /// said anything.
    Grouped(Verdict, Option<Ruling>),
}

/// A matched vulnerability and what the distributor's data said about it.
struct Ruled<'a> {
    vulnerability: Vulnerability<'a>,
    ruling: Option<Ruling>,
}

/// What every finding drawn from one identification shares.
struct Context<'j, 'a> {
    judged: &'j Judged<'j>,
    /// Where the build was placed among the distributor's releases.
    placement: Option<&'j Placement<'a>>,
    /// Or why it could not be.
    unplaced: Option<&'j Unplaced>,
}

impl Context<'_, '_> {
    /// Who built the service, as a person reads it, or `the distributor`
    /// where it is an upstream build and nothing needs to name one.
    fn distributor_label(&self) -> &'static str {
        self.judged
            .build
            .map_or("the distributor", |build| build.distributor().label())
    }

    /// The release the verdicts are about, or `unknown`.
    fn release(&self) -> &str {
        self.placement
            .map(|placed| placed.release.as_str())
            .or_else(|| {
                self.judged
                    .build
                    .and_then(|build| build.release())
                    .map(|release| release.name())
            })
            .unwrap_or("unknown")
    }

    /// The source package the verdicts are about.
    fn package(&self) -> &str {
        self.placement
            .map_or("the package", |placed| placed.package)
    }

    /// The placed build in one phrase: `openssh 1:6.6p1-2ubuntu2.13 on Ubuntu
    /// 14.04`, or without the version where the banner gave no revision.
    fn placed_as(&self) -> String {
        let distributor = self.distributor_label();
        match self.placement {
            Some(placed) => {
                let inferred = match placed.release_inferred {
                    true => ", the only release that shipped this build",
                    false => "",
                };
                match &placed.installed {
                    Some(version) => format!(
                        "{} {version} on {distributor} {}{inferred}",
                        placed.package, placed.release
                    ),
                    None => format!("{} on {distributor} {}", placed.package, placed.release),
                }
            }
            None => format!("This {distributor} build"),
        }
    }

    /// What a claim of kind `verdict` about this identification is about.
    ///
    /// The software and its version, whose build it is and which release,
    /// and the kind of verdict:
    /// `openbsd:openssh:6.6.1p1@ubuntu-14.04/fix-available`. Not a
    /// vulnerability identifier, because the set behind a summary moves with
    /// the data: a catalogue refresh adds entries and a distributor's fix data
    /// withdraws them, and a claim keyed on any one member would rename itself
    /// with every change and read, in a comparison of two scans of an unchanged
    /// host, as one finding gone and another arrived.
    fn subject(&self, verdict: Verdict) -> String {
        let parsed = &self.judged.parsed;
        let scope = match self.judged.build {
            None => "upstream".to_string(),
            Some(build) => {
                let distributor = wire::distributor_name(build.distributor());
                let release = self
                    .placement
                    .map(|placed| placed.release.as_str())
                    .or_else(|| build.release().map(|release| release.name()));
                match release {
                    Some(release) => format!("{distributor}-{release}"),
                    None => distributor.to_string(),
                }
            }
        };
        format!(
            "{}:{}:{}@{scope}/{}",
            parsed.vendor,
            parsed.product,
            parsed.version,
            verdict.key()
        )
    }
}

/// What the distributor says about why the vulnerabilities of a
/// [`Verdict::NoFix`] group stay open, as a clause.
fn open_kinds(entries: &[Ruled<'_>]) -> String {
    let (mut ignored, mut other) = (0usize, 0usize);
    for entry in entries {
        if let Some(Ruling::Vulnerable(Vulnerable::NoFix { kind, .. })) = &entry.ruling {
            match kind {
                OpenKind::Ignored => ignored += 1,
                _ => other += 1,
            }
        }
    }
    match (ignored, other) {
        (0, _) => String::new(),
        (_, 0) => ": it has said it will not fix them in this release".to_string(),
        (ignored, other) => format!(
            ": it has said it will not fix {ignored} of them in this release, and {other} await \
             a fix"
        ),
    }
}

/// The distributor's own ratings of a group's vulnerabilities, as a sentence,
/// where it rated any. Information for a reader, never the severity: the
/// severity stays the one scale every product and distribution shares.
fn priorities(context: &Context<'_, '_>, entries: &[Ruled<'_>]) -> Option<String> {
    let placement = context.placement?;
    let mut counts: Vec<(&str, usize)> = Vec::new();
    for entry in entries {
        if let Some(priority) = placement
            .advisories
            .priority(Some(&placement.release), entry.vulnerability.cve)
        {
            match counts.iter_mut().find(|(seen, _)| *seen == priority) {
                Some((_, count)) => *count += 1,
                None => counts.push((priority, 1)),
            }
        }
    }
    if counts.is_empty() {
        return None;
    }
    let rated = counts
        .iter()
        .map(|(priority, count)| format!("{count} {priority}"))
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "{}'s own priority for them: {rated}",
        context.distributor_label()
    ))
}

/// What to do about a group, where the distributor's data says.
fn remediation(
    context: &Context<'_, '_>,
    verdict: Verdict,
    entries: &[Ruled<'_>],
) -> Option<String> {
    let distributor = context.distributor_label();
    // The newest fix any of them needs, since installing it fixes all of them,
    // and the notices that published fixes, three at most.
    let fixes = || {
        entries.iter().filter_map(|entry| match &entry.ruling {
            Some(Ruling::Vulnerable(Vulnerable::FixAvailable(fix) | Vulnerable::EsmOnly(fix)))
            | Some(Ruling::Unsettled(Unsettled::PatchLevelHidden(fix))) => Some(fix),
            _ => None,
        })
    };
    let newest = fixes()
        .map(|fix| fix.version.as_str())
        .max_by(|a, b| crate::version::dpkg_cmp(a, b));
    let mut notices: Vec<&str> = Vec::new();
    for fix in fixes() {
        if let Some(notice) = fix.advisory.as_deref()
            && !notices.contains(&notice)
            && notices.len() < MAX_NAMED_IN_EXCERPT
        {
            notices.push(notice);
        }
    }
    let citing = match notices.is_empty() {
        true => String::new(),
        false => format!(" ({})", notices.join(", ")),
    };
    let package = context.package();
    match verdict {
        Verdict::FixAvailable => Some(format!(
            "Upgrade {package} to {} or later{citing}.",
            newest?
        )),
        Verdict::EsmOnly => Some(format!(
            "Enable Ubuntu Pro and upgrade {package} to {} or later{citing}, or move to a \
             supported Ubuntu release.",
            newest?
        )),
        Verdict::NoFix => Some(format!(
            "{distributor} has published no fix for release {}; moving to a supported release \
             is the remedy.",
            context.release()
        )),
        Verdict::PatchLevelHidden => Some(format!(
            "Check that {package} is at {} or later{citing}.",
            newest?
        )),
        Verdict::BuildUnchecked => Some(format!(
            "Compare the installed package with {distributor}'s security advisories for this \
             release."
        )),
        Verdict::Affected | Verdict::NeedsSetting | Verdict::AnyVersion | Verdict::Untriaged => {
            None
        }
    }
}

/// What a correlation is judging: one platform identifier of one service, and
/// what the service said about whose build it is.
struct Judged<'a> {
    /// The identifier, as the service carries it.
    cpe: &'a str,
    /// The same, split into what the catalogue matches on.
    parsed: Cpe,
    /// The service's own name for the software, for titles.
    product: Option<&'a str>,
    /// Whose build the service is, where it said.
    build: Option<&'a Build>,
}

impl<'a> Judged<'a> {
    /// One identifier of `service`, or [`None`] for one that is not a CPE.
    fn of(service: &'a Service, cpe: &'a str) -> Option<Self> {
        Some(Self {
            cpe,
            parsed: Cpe::parse(cpe)?,
            product: service.product(),
            build: service.build(),
        })
    }

    /// A bare identifier, judged as the upstream release it names.
    #[cfg(test)]
    fn upstream(cpe: &'a str) -> Option<Self> {
        Some(Self {
            cpe,
            parsed: Cpe::parse(cpe)?,
            product: None,
            build: None,
        })
    }

    /// The catalogue's key for the software: `openbsd:openssh`.
    fn vendor_product(&self) -> String {
        format!("{}:{}", self.parsed.vendor, self.parsed.product)
    }
}

/// The kinds of claim a correlation makes, one finding each.
///
/// Ordered by how surely the claim holds and then by how directly it follows
/// from what was matched, which is the order a report lists them in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Verdict {
    /// An entry naming a version range was checked against the version found,
    /// on a service that is the upstream release that version names. As sure
    /// as a version string makes anything: [`Confidence::Probable`].
    Affected,
    /// The distributor fixed it in a build of this release newer than the one
    /// the service runs: [`Confidence::Probable`], with the build to install.
    FixAvailable,
    /// Ubuntu fixed it only in its paid ESM pockets, and the service does not
    /// run that build: [`Confidence::Probable`].
    EsmOnly,
    /// The distributor has not fixed it in this release, and has said so, or
    /// has said it will not: [`Confidence::Probable`] whatever the build.
    NoFix,
    /// A vulnerability that reaches the service only where it is configured
    /// in a way it is not by default: an sshd option, an Apache module. The
    /// scan cannot see the configuration, so the claim is as good as the
    /// chance the setting is on: [`Confidence::Weak`].
    NeedsSetting,
    /// A range check on a distribution's build that the distributor's own
    /// data could not be asked about: none was loaded, it does not cover the
    /// release, or the release could not be told.
    ///
    /// A distribution fixes vulnerabilities by patching the release it ships
    /// and publishing a new build, leaving the upstream version where it was,
    /// so the check says the upstream release had these vulnerabilities and
    /// says nothing about whether this build still does. Against a
    /// long-maintained release most of them are fixed. Reported, because the
    /// build may still carry any of them, and at [`Confidence::Weak`], because
    /// the version was never the question.
    BuildUnchecked,
    /// The distributor fixed it in some build of the release, and the banner
    /// does not say which build this is, as `Apache/2.4.7 (Ubuntu)` does not:
    /// [`Confidence::Weak`], since the build may predate the fix or carry it.
    PatchLevelHidden,
    /// The distributor has not judged it for this release, or holds no record
    /// of it: [`Confidence::Weak`], on the upstream version's word alone.
    Untriaged,
    /// An entry whose `affected` is `*` names a product and no version at all,
    /// so it matches a patched installation exactly as readily as a vulnerable
    /// one: [`Confidence::Weak`].
    AnyVersion,
}

impl Verdict {
    /// Where `vulnerability` goes, on `judged`, placed as `placement` says.
    ///
    /// Where a vulnerability lives comes first. A flaw in the client programs
    /// installed beside a daemon, or one that needs an account on the host,
    /// is not something a scan of the listening service has found, however
    /// the version compares; the overlay in [`applicability`] says which those
    /// are. Then, for a distribution's build, what the distributor's data
    /// says, since a vulnerability the build does not carry needs no setting
    /// to be withdrawn.
    fn of(
        vulnerability: &Vulnerability<'_>,
        judged: &Judged<'_>,
        placement: Option<&Result<Placement<'_>, Unplaced>>,
    ) -> Classified {
        let applies = vulnerability.applies().map(|found| found.applies);
        if matches!(applies, Some(Applies::Client | Applies::Local)) {
            return Classified::Withdrawn(Why::Elsewhere);
        }
        let needs_setting = matches!(applies, Some(Applies::Configuration { .. }));

        let (verdict, ruling) = match placement {
            Some(Ok(placed)) => match placed.rule(vulnerability.cve) {
                Ruling::Withdrawn(Withdrawal::Fixed { .. }) => {
                    return Classified::Withdrawn(Why::Fixed);
                }
                Ruling::Withdrawn(Withdrawal::NotAffected { .. }) => {
                    return Classified::Withdrawn(Why::NotAffected);
                }
                ruling => {
                    let verdict = match &ruling {
                        Ruling::Vulnerable(Vulnerable::FixAvailable(_)) => Self::FixAvailable,
                        Ruling::Vulnerable(Vulnerable::EsmOnly(_)) => Self::EsmOnly,
                        Ruling::Vulnerable(Vulnerable::NoFix { .. }) => Self::NoFix,
                        Ruling::Unsettled(Unsettled::PatchLevelHidden(_)) => Self::PatchLevelHidden,
                        Ruling::Unsettled(Unsettled::Untriaged | Unsettled::NotTracked) => {
                            Self::Untriaged
                        }
                        Ruling::Withdrawn(_) => unreachable!("handled above"),
                    };
                    (verdict, Some(ruling))
                }
            },
            Some(Err(_)) | None => {
                let verdict = match (vulnerability.constrains_the_version(), judged.build) {
                    (false, _) => Self::AnyVersion,
                    (true, None) => Self::Affected,
                    (true, Some(_)) => Self::BuildUnchecked,
                };
                (verdict, None)
            }
        };
        match needs_setting {
            true => Classified::Grouped(Self::NeedsSetting, ruling),
            false => Classified::Grouped(verdict, ruling),
        }
    }

    /// The name a claim's subject carries for it, fixed because claims are
    /// keyed on it.
    const fn key(self) -> &'static str {
        match self {
            Self::Affected => "affected",
            Self::FixAvailable => "fix-available",
            Self::EsmOnly => "esm-only",
            Self::NoFix => "no-fix",
            Self::NeedsSetting => "needs-setting",
            Self::BuildUnchecked => "build-unchecked",
            Self::PatchLevelHidden => "patch-level-hidden",
            Self::Untriaged => "untriaged",
            Self::AnyVersion => "any-version",
        }
    }

    /// How sure a claim of this kind is.
    const fn confidence(self) -> Confidence {
        match self {
            Self::Affected | Self::FixAvailable | Self::EsmOnly | Self::NoFix => {
                Confidence::Probable
            }
            Self::NeedsSetting
            | Self::BuildUnchecked
            | Self::PatchLevelHidden
            | Self::Untriaged
            | Self::AnyVersion => Confidence::Weak,
        }
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

    /// What the applicability overlay says about this vulnerability of this
    /// product, where it says anything.
    fn applies(&self) -> Option<applicability::Applicability> {
        applicability::applicability(self.cve, &format!("{}:{}", self.vendor, self.product))
    }

    /// The non-default setting this vulnerability needs, where it needs one.
    fn requires(&self) -> Option<&'static str> {
        match self.applies()?.applies {
            Applies::Configuration { requires } => Some(requires),
            _ => None,
        }
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
        let fields: Vec<String> = match cpe.strip_prefix("cpe:2.3:") {
            Some(body) => formatted_fields(body),
            None => cpe
                .strip_prefix("cpe:/")?
                .split(':')
                .map(str::to_owned)
                .collect(),
        };
        let mut fields = fields.iter().map(String::as_str);
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

/// The fields of a CPE 2.3 formatted string after its `cpe:2.3:` prefix, split
/// and unescaped.
///
/// The 2.3 grammar quotes punctuation inside a field with a backslash, so a
/// release NVD writes as `7.03hp3\+ftf` is `7.03hp3+ftf` and a colon inside a
/// field is `\:` rather than a separator. Read literally, the escaped form
/// equals no version any banner states, and a field holding an escaped colon
/// splits in two.
pub(crate) fn formatted_fields(body: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut characters = body.chars();
    while let Some(character) = characters.next() {
        match character {
            '\\' => field.extend(characters.next()),
            ':' => fields.push(std::mem::take(&mut field)),
            other => field.push(other),
        }
    }
    fields.push(field);
    fields
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
    /// Regenerating the catalogue can give rows to names listed here, which is
    /// what the second test below is for: a stale exemption is as quiet a
    /// defect as the gap it records.
    ///
    /// The join is `vendor:product` and a mismatch is silent in both directions:
    /// a scan identifies the software, the catalogue holds records for it, and
    /// nothing correlates because the two spell it differently. A rule emitting
    /// `microsoft:iis` is such a mismatch, since that spelling belongs to a
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
        // Every record NVD holds against these is stated for one platform
        // only, which the conversion leaves out.
        ("vandyke:vshell", "its one record holds only on Windows"),
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

    /// A summary is a phrase, and an entry with no title of its own does not get
    /// to put a paragraph on that line.
    ///
    /// NVD publishes no title, so `import::nvd` cuts the description to fit and
    /// almost every one comes out at the cap. IIS 8.5 is the case that showed
    /// it: one match, and the summary read `The IP Security feature in Microsoft
    /// Internet Information Services (IIS) 8.0 and 8.5 does not properly process
    /// wildcard allow and deny rules for domains within`, cut mid-sentence, in a
    /// column whose other rows are six words.
    #[test]
    fn a_description_too_long_to_be_a_summary_becomes_one_and_moves_to_the_excerpt() {
        let long = "The IP Security feature in Microsoft Internet Information Services (IIS) \
                    8.0 and 8.5 does not properly process wildcard allow and deny rules for \
                    domains within";
        let document = format!(
            "id = \"test:cve\"\nversion = \"1.0.0\"\n\n\
             [[vulnerability]]\ncve = \"CVE-2014-4078\"\ntitle = \"{long}\"\n\
             severity = \"medium\"\nvendor = \"microsoft\"\n\
             product = \"internet_information_services\"\naffected = \"== 8.5\"\n"
        );
        let catalogue =
            Catalogue::read(&mut document.as_bytes()).expect("a catalogue naming one entry");

        let findings = catalogue.findings_for("cpe:/a:microsoft:internet_information_services:8.5");
        let finding = findings.first().expect("the entry matches");

        assert_eq!(
            finding.title(),
            "internet_information_services 8.5 has 1 known vulnerability"
        );
        let excerpt = finding.excerpt().as_str();
        assert!(
            excerpt.contains("IP Security feature"),
            "the description is kept as evidence, not discarded: {excerpt}"
        );
    }

    /// And an entry that does have a title keeps it. This is what the shipped
    /// seed and a converted KEV record produce.
    #[test]
    fn a_title_short_enough_to_be_a_summary_is_used_as_one() {
        let document = "id = \"test:cve\"\nversion = \"1.0.0\"\n\n\
             [[vulnerability]]\ncve = \"CVE-2021-41773\"\n\
             title = \"Apache HTTP Server path traversal and RCE\"\n\
             severity = \"critical\"\nvendor = \"apache\"\nproduct = \"http_server\"\n\
             affected = \"== 2.4.49\"\n";
        let catalogue = Catalogue::read(&mut document.as_bytes()).expect("a catalogue");

        let findings = catalogue.findings_for("cpe:/a:apache:http_server:2.4.49");
        assert_eq!(
            findings.first().expect("the entry matches").title(),
            "Apache HTTP Server path traversal and RCE"
        );
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

    /// The 2.3 grammar quotes punctuation in a field with a backslash, and a
    /// release NVD writes `7.03hp3\\+ftf` is the `7.03hp3+ftf` a banner
    /// states. An escaped colon is part of its field, not a separator.
    #[test]
    fn an_escaped_character_in_a_2_3_cpe_is_read_as_itself() {
        let cpe = Cpe::parse("cpe:2.3:a:acme:ftpd:7.03hp3\\+ftf:*:*:*:*:*:*:*").expect("parses");
        assert_eq!(cpe.version, "7.03hp3+ftf");
        assert_eq!(
            formatted_fields("a:acme:ftp\\:d:1.0"),
            ["a", "acme", "ftp:d", "1.0"]
        );
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

    /// A catalogue of three vulnerabilities in one release, the worst with a
    /// weakness and a remedy of its own.
    fn three_in_one_release() -> Catalogue {
        let mut document = String::from("id = \"acme:advisories\"\nversion = \"1.0.0\"\n");
        for (index, severity) in ["critical", "high", "medium"].iter().enumerate() {
            document.push_str(&format!(
                "\n[[vulnerability]]\ncve = \"CVE-2016-{:04}\"\ntitle = \"Entry {index}\"\n\
                 severity = \"{severity}\"\nvendor = \"openbsd\"\nproduct = \"openssh\"\n\
                 affected = \"< 7.0\"\ncwe = 287\nremediation = \"Upgrade.\"\n",
                index + 1
            ));
        }
        Catalogue::read(&mut document.as_bytes()).expect("a valid document")
    }

    fn openssh(build: Option<crate::model::port::Build>) -> Service {
        let service = Service::new("ssh", 100)
            .with_product("OpenSSH")
            .with_version("6.6.1p1")
            .with_cpe("cpe:/a:openbsd:openssh:6.6.1p1");
        match build {
            Some(build) => service.with_build(build),
            None => service,
        }
    }

    fn judged(catalogue: &Catalogue, service: &Service) -> Vec<Finding> {
        service
            .cpes()
            .iter()
            .filter_map(|cpe| Judged::of(service, cpe))
            .flat_map(|judged| catalogue.judge(&judged, &[]).findings)
            .collect()
    }

    /// A range match against a distribution's build says the upstream release
    /// had these vulnerabilities and nothing about whether the build still
    /// does: the distributor backports fixes without moving the version. So it
    /// is reported, and never as surely as the same match against the
    /// upstream release, which is what a patched Ubuntu server printed as
    /// critical and probable looked like.
    #[test]
    fn a_distribution_builds_version_match_is_weak_and_says_why() {
        use crate::model::port::{Build, Distributor, Release, ReleaseBasis};

        let catalogue = three_in_one_release();
        let build = Build::new(Distributor::Ubuntu)
            .with_revision("2ubuntu2.13")
            .with_release(Release::new("14.04", ReleaseBasis::Banner));

        let upstream = judged(&catalogue, &openssh(None));
        assert_eq!(upstream.len(), 1);
        assert_eq!(upstream[0].confidence(), Confidence::Probable);
        assert_eq!(
            upstream[0].title(),
            "OpenSSH 6.6.1p1 has 3 known vulnerabilities"
        );
        assert!(upstream[0].build().is_none());

        let distributed = judged(&catalogue, &openssh(Some(build.clone())));
        assert_eq!(distributed.len(), 1);
        let finding = &distributed[0];
        assert_eq!(finding.confidence(), Confidence::Weak);
        assert_eq!(
            finding.severity(),
            Severity::Critical,
            "how bad if true is unchanged"
        );
        assert_eq!(
            finding.title(),
            "OpenSSH 6.6.1p1: 3 upstream CVEs, build unchecked"
        );
        assert!(
            finding
                .excerpt()
                .as_str()
                .contains("Ubuntu backports fixes")
        );
        assert!(
            finding
                .excerpt()
                .as_str()
                .contains("Ubuntu 14.04 2ubuntu2.13")
        );
        assert_eq!(
            finding.build(),
            Some(&build),
            "the claim rests on the build"
        );
        assert_eq!(
            finding.subject(),
            Some("openbsd:openssh:6.6.1p1@ubuntu-14.04/build-unchecked")
        );
    }

    /// A weakness and a remedy describe one vulnerability. A summary of three
    /// carrying the worst one's would print it beside the count as if it
    /// characterised all three; a single match keeps its own.
    #[test]
    fn a_summary_carries_no_single_entrys_weakness_or_remedy() {
        let catalogue = three_in_one_release();
        let summary = &judged(&catalogue, &openssh(None))[0];
        assert!(
            !summary
                .references()
                .any(|reference| matches!(reference, Reference::Cwe(_))),
            "{:?}",
            summary.references().collect::<Vec<_>>()
        );
        assert_eq!(summary.remediation(), None);

        let one = Catalogue::read(
            &mut "id = \"acme:one\"\nversion = \"1.0.0\"\n\n[[vulnerability]]\n\
                  cve = \"CVE-2016-0001\"\ntitle = \"One\"\nseverity = \"high\"\n\
                  vendor = \"openbsd\"\nproduct = \"openssh\"\naffected = \"< 7.0\"\n\
                  cwe = 287\nremediation = \"Upgrade.\"\n"
                .as_bytes(),
        )
        .expect("a valid document");
        let single = &judged(&one, &openssh(None))[0];
        assert!(
            single
                .references()
                .any(|reference| *reference == Reference::cwe(287))
        );
        assert_eq!(single.remediation(), Some("Upgrade."));
    }

    /// A claim is keyed on what it is about, so a catalogue refresh that adds a
    /// vulnerability below the lowest one it cited leaves the claim where it
    /// was: keyed on its lowest identifier, it would rename itself and a
    /// comparison of two scans of an unchanged host would report one finding
    /// gone and another arrived.
    #[test]
    fn a_claim_survives_the_set_of_vulnerabilities_behind_it_changing() {
        let catalogue = three_in_one_release();
        let before = judged(&catalogue, &openssh(None))[0].claim_id();

        let mut document = String::from("id = \"acme:advisories\"\nversion = \"1.0.1\"\n");
        document.push_str(
            "\n[[vulnerability]]\ncve = \"CVE-2001-0001\"\ntitle = \"Older\"\n\
             severity = \"low\"\nvendor = \"openbsd\"\nproduct = \"openssh\"\naffected = \"< 7.0\"\n",
        );
        let refreshed = Catalogue::read(&mut document.as_bytes()).expect("a valid document");
        let after = judged(&refreshed, &openssh(None))[0].claim_id();
        assert_eq!(before.subject(), after.subject());
    }

    /// A correlation is recomputed, not observed again: correlating a second
    /// time against data that no longer draws a claim withdraws it, where
    /// adding would have left the stale claim beside the new one.
    #[test]
    fn correlating_again_replaces_what_the_same_catalogue_drew_before() {
        use crate::model::host::Host;
        use crate::model::port::{Build, Distributor, Port, PortState};

        let catalogue = three_in_one_release();
        let mut host = Host::new("192.0.2.1".parse().expect("an address"));
        host.add_port(Port::new(22, Protocol::Tcp, PortState::Open).with_service(openssh(None)));
        correlate_with(&mut host, &catalogue);
        let subjects = |host: &Host| -> Vec<String> {
            host.ports()
                .flat_map(|port| port.findings())
                .filter_map(|finding| finding.subject().map(str::to_owned))
                .collect()
        };
        assert_eq!(
            subjects(&host),
            ["openbsd:openssh:6.6.1p1@upstream/affected"]
        );

        // The same port, now known to be Ubuntu's build.
        let mut rescanned = host.clone();
        rescanned.add_port(
            Port::new(22, Protocol::Tcp, PortState::Open)
                .with_service(openssh(Some(Build::new(Distributor::Ubuntu)))),
        );
        correlate_with(&mut rescanned, &catalogue);
        assert_eq!(
            subjects(&rescanned),
            ["openbsd:openssh:6.6.1p1@ubuntu/build-unchecked"],
            "the upstream claim is withdrawn, not kept beside its replacement"
        );
    }

    /// A flaw in the client programs installed beside a daemon is not
    /// something a scan of the daemon found. ssh-agent's CVE-2023-38408 is
    /// reached through an agent somebody forwarded to a hostile machine, and a
    /// listening sshd charged with it is a false finding; it is counted in the
    /// excerpt so the identifiers still reconcile. A flaw that needs a setting
    /// the service does not ship with is its own, weaker claim.
    #[test]
    fn a_client_side_flaw_is_withdrawn_and_a_configuration_one_is_its_own_claim() {
        let findings = Catalogue::embedded().findings_for("cpe:/a:openbsd:openssh:6.6.1p1");
        let cited: Vec<&str> = findings
            .iter()
            .flat_map(|finding| finding.references())
            .filter_map(|reference| match reference {
                Reference::Cve(id) => Some(id.as_str()),
                _ => None,
            })
            .collect();
        assert!(!cited.contains(&"CVE-2023-38408"), "{cited:?}");
        assert!(
            findings.iter().any(|finding| finding
                .excerpt()
                .as_str()
                .contains("None of these is reported")),
            "the withdrawn ones are counted somewhere a reader can see"
        );
        let setting = findings
            .iter()
            .find(|finding| {
                finding
                    .subject()
                    .is_some_and(|subject| subject.ends_with("/needs-setting"))
            })
            .expect("6.6.1p1 carries flaws that need a non-default setting");
        assert_eq!(setting.confidence(), Confidence::Weak);
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
        // version range actually makes, and asserting emptiness here would hold
        // only for a catalogue of a few hand-picked entries.
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
        let first: Vec<Finding> = port.findings().cloned().collect();
        assert!(!first.is_empty(), "the vulnerable service got findings");

        // A second pass reaches the same claims rather than adding more.
        correlate(&mut host);
        let port = host.ports().find(|p| p.number() == 80).unwrap();
        assert_eq!(port.findings().cloned().collect::<Vec<_>>(), first);
    }

    /// A correlation says which identifier it matched, in a field and not only
    /// in the excerpt, since the claim rests on it and a merge asks whether a
    /// newer identification still backs it.
    #[test]
    fn a_correlation_names_the_identifier_it_was_drawn_from() {
        use crate::model::host::Host;
        use crate::model::port::{Port, PortState, Service};
        use std::net::{IpAddr, Ipv4Addr};

        let cpe = "cpe:/a:apache:http_server:2.4.49";
        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        host.add_port(
            Port::new(80, Protocol::Tcp, PortState::Open)
                .with_service(Service::new("http", 90).with_cpe(cpe)),
        );

        correlate(&mut host);
        let port = host.ports().find(|p| p.number() == 80).unwrap();
        assert!(port.findings().count() > 0, "the release draws findings");
        assert!(
            port.findings()
                .all(|finding| finding.cpes().collect::<Vec<_>>() == [cpe])
        );
    }
}

/// A distribution's build judged against its distributor's own data.
#[cfg(test)]
mod verdicts {
    use super::advisories::{Builder, Channel, Distributor as Data, OpenKind, Standing, Status};
    use super::*;
    use crate::model::port::{Build, Distributor, Release, ReleaseBasis};

    fn status(channel: Channel, standing: Standing, advisory: Option<&str>) -> Status {
        Status {
            channel,
            standing,
            advisory: advisory.map(str::to_owned),
        }
    }

    fn fixed(version: &str) -> Standing {
        Standing::Fixed {
            version: version.to_owned(),
        }
    }

    /// Ubuntu 14.04's openssh as its data could describe it: one vulnerability
    /// of each kind a verdict can reach. The identifiers are ones no overlay
    /// classifies, so the data alone decides.
    fn ubuntu() -> Advisories {
        let mut builder = Builder::new(Data::Ubuntu);
        let mut record = |cve: &str, status: Status| {
            builder.record("14.04", "openssh", cve, status);
        };
        record(
            "CVE-2099-0001",
            status(
                Channel::Archive,
                fixed("1:6.6p1-2ubuntu2.7"),
                Some("USN-9001-1"),
            ),
        );
        record(
            "CVE-2099-0002",
            status(
                Channel::Archive,
                fixed("1:6.6p1-2ubuntu2.20"),
                Some("USN-9002-1"),
            ),
        );
        record(
            "CVE-2099-0003",
            status(
                Channel::Esm,
                fixed("1:6.6p1-2ubuntu2.13+esm1"),
                Some("USN-9003-2"),
            ),
        );
        record(
            "CVE-2099-0004",
            status(
                Channel::Archive,
                Standing::Open {
                    kind: OpenKind::Ignored,
                    note: Some("end of standard support".into()),
                },
                None,
            ),
        );
        record(
            "CVE-2099-0005",
            status(Channel::Esm, Standing::NotAffected { reason: None }, None),
        );
        record(
            "CVE-2099-0006",
            status(
                Channel::Archive,
                Standing::Open {
                    kind: OpenKind::NeedsTriage,
                    note: None,
                },
                None,
            ),
        );
        builder.versions(
            "14.04",
            "openssh",
            [
                "1:6.6p1-2ubuntu1",
                "1:6.6p1-2ubuntu2.7",
                "1:6.6p1-2ubuntu2.13",
                "1:6.6p1-2ubuntu2.20",
            ],
        );
        builder.dated("2026-09-28T00:00:00Z");
        builder.finish()
    }

    /// Seven vulnerabilities of OpenSSH below 7.0, the seventh one the data
    /// has no record of.
    fn catalogue() -> Catalogue {
        let mut document = String::from("id = \"acme:advisories\"\nversion = \"1.0.0\"\n");
        for index in 1..=7 {
            document.push_str(&format!(
                "\n[[vulnerability]]\ncve = \"CVE-2099-{index:04}\"\ntitle = \"Entry {index}\"\n\
                 severity = \"high\"\nvendor = \"openbsd\"\nproduct = \"openssh\"\n\
                 affected = \"< 7.0\"\n"
            ));
        }
        Catalogue::read(&mut document.as_bytes()).expect("a valid document")
    }

    fn ubuntu_build(revision: Option<&str>, release: Option<&str>) -> Build {
        let mut build = Build::new(Distributor::Ubuntu);
        if let Some(release) = release {
            build = build.with_release(Release::new(release, ReleaseBasis::Banner));
        }
        if let Some(revision) = revision {
            build = build.with_revision(revision);
        }
        build
    }

    fn judge(build: Build, advisories: &[Advisories]) -> Judgement {
        let service = Service::new("ssh", 100)
            .with_product("OpenSSH")
            .with_version("6.6.1p1")
            .with_cpe("cpe:/a:openbsd:openssh:6.6.1p1")
            .with_build(build);
        let judged = Judged::of(&service, "cpe:/a:openbsd:openssh:6.6.1p1").expect("a CPE");
        catalogue().judge(&judged, advisories)
    }

    fn kinds(judgement: &Judgement) -> Vec<(String, Confidence, Vec<String>)> {
        judgement
            .findings
            .iter()
            .map(|finding| {
                let kind = finding
                    .subject()
                    .and_then(|subject| subject.rsplit('/').next())
                    .unwrap_or_default()
                    .to_owned();
                let cves = finding
                    .references()
                    .filter_map(|reference| match reference {
                        Reference::Cve(id) => Some(id.clone()),
                        _ => None,
                    })
                    .collect();
                (kind, finding.confidence(), cves)
            })
            .collect()
    }

    /// Each vulnerability goes where the distributor's verdict on this build
    /// puts it: fixed below the build or never carried is withdrawn, fixed
    /// above it is a vulnerability with the build to install, fixed only in
    /// ESM or not at all is a vulnerability, and one the data leaves open
    /// stays unsettled.
    #[test]
    fn a_placed_build_is_judged_vulnerability_by_vulnerability() {
        let data = [ubuntu()];
        let judgement = judge(ubuntu_build(Some("2ubuntu2.13"), Some("14.04")), &data);

        assert_eq!(
            kinds(&judgement),
            [
                (
                    "fix-available".into(),
                    Confidence::Probable,
                    vec!["CVE-2099-0002".into()]
                ),
                (
                    "esm-only".into(),
                    Confidence::Probable,
                    vec!["CVE-2099-0003".into()]
                ),
                (
                    "no-fix".into(),
                    Confidence::Probable,
                    vec!["CVE-2099-0004".into()]
                ),
                (
                    "untriaged".into(),
                    Confidence::Weak,
                    vec!["CVE-2099-0006".into(), "CVE-2099-0007".into()]
                ),
            ]
        );
        assert_eq!(
            judgement.withdrawn,
            Withdrawn {
                fixed: 1,
                not_affected: 1,
                elsewhere: 0
            }
        );

        let upgrade = &judgement.findings[0];
        assert_eq!(
            upgrade.remediation(),
            Some("Upgrade openssh to 1:6.6p1-2ubuntu2.20 or later (USN-9002-1).")
        );
        assert_eq!(
            upgrade.advised_by().map(DetectionId::id),
            Some("ubuntu:security-notices"),
            "the finding names the data that judged it"
        );
        assert!(
            upgrade
                .excerpt()
                .as_str()
                .contains("openssh 1:6.6p1-2ubuntu2.13 on Ubuntu 14.04"),
            "{}",
            upgrade.excerpt().as_str()
        );
        assert_eq!(
            upgrade.subject(),
            Some("openbsd:openssh:6.6.1p1@ubuntu-14.04/fix-available")
        );
    }

    /// A banner that names the revision and not the release is placed by the
    /// one release whose package ever had that revision, and judged the same.
    #[test]
    fn a_build_is_placed_in_the_one_release_that_shipped_its_revision() {
        let data = [ubuntu()];
        let named = judge(ubuntu_build(Some("2ubuntu2.13"), Some("14.04")), &data);
        let placed = judge(ubuntu_build(Some("2ubuntu2.13"), None), &data);
        assert_eq!(kinds(&named), kinds(&placed));
        assert!(
            placed.findings[0]
                .excerpt()
                .as_str()
                .contains("the only release that shipped this build")
        );
    }

    /// A banner that says whose build it is and not which build leaves every
    /// vulnerability the distributor fixed unsettled: the build may predate
    /// the fix or carry it. What the distributor never fixed in the release is
    /// a vulnerability whatever the build.
    #[test]
    fn a_hidden_patch_level_leaves_what_was_fixed_unsettled() {
        let data = [ubuntu()];
        let judgement = judge(ubuntu_build(None, Some("14.04")), &data);
        let kinds = kinds(&judgement);
        assert!(kinds.contains(&(
            "patch-level-hidden".into(),
            Confidence::Weak,
            vec![
                "CVE-2099-0001".into(),
                "CVE-2099-0002".into(),
                "CVE-2099-0003".into()
            ]
        )));
        assert!(kinds.contains(&(
            "no-fix".into(),
            Confidence::Probable,
            vec!["CVE-2099-0004".into()]
        )));
    }

    /// With no data for the build's distributor, or none at all, the build is
    /// judged as far as its upstream version goes, and the excerpt says why.
    #[test]
    fn a_build_the_data_cannot_place_is_reported_unchecked_and_says_why() {
        let none = judge(ubuntu_build(Some("2ubuntu2.13"), Some("14.04")), &[]);
        assert_eq!(none.findings.len(), 1);
        assert!(
            none.findings[0]
                .excerpt()
                .as_str()
                .contains("no Ubuntu advisory data was loaded")
        );

        let data = [ubuntu()];
        let elsewhere = judge(ubuntu_build(Some("2ubuntu2.13"), Some("16.04")), &data);
        assert!(
            elsewhere.findings[0]
                .excerpt()
                .as_str()
                .contains("does not cover release 16.04"),
            "{}",
            elsewhere.findings[0].excerpt().as_str()
        );
        assert!(
            elsewhere.findings[0]
                .subject()
                .is_some_and(|subject| subject.ends_with("/build-unchecked"))
        );
    }

    /// The acceptance case, on the distributors' real data: the scanme banner
    /// `OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13` against what Ubuntu publishes. A
    /// fix Ubuntu shipped in 2ubuntu2.2 is withdrawn, a vulnerability its data
    /// says 14.04 never had is withdrawn, and two flaws of the client programs
    /// (ssh-agent's, and the algorithm-ordering leak), which the daemon does
    /// not carry, are withdrawn on the overlay's word before the data is
    /// asked.
    #[cfg(feature = "import-distro")]
    #[test]
    fn scanmes_openssh_is_judged_against_ubuntus_own_data() {
        let ubuntu = crate::import::ubuntu::read(
            &mut &include_bytes!("../tests/data/distro/ubuntu-osv.tar.xz")[..],
            &mut &include_bytes!("../tests/data/distro/ubuntu-vex.tar.xz")[..],
        )
        .expect("the fixture converts");

        let mut document = String::from("id = \"acme:advisories\"\nversion = \"1.0.0\"\n");
        for cve in [
            "CVE-2015-5600",
            "CVE-2016-10010",
            "CVE-2020-14145",
            "CVE-2023-38408",
        ] {
            document.push_str(&format!(
                "\n[[vulnerability]]\ncve = \"{cve}\"\ntitle = \"{cve}\"\nseverity = \"high\"\n\
                 vendor = \"openbsd\"\nproduct = \"openssh\"\naffected = \"< 7.0\"\n"
            ));
        }
        let catalogue = Catalogue::read(&mut document.as_bytes()).expect("a valid document");
        let service = Service::new("ssh", 100)
            .with_product("OpenSSH")
            .with_version("6.6.1p1")
            .with_cpe("cpe:/a:openbsd:openssh:6.6.1p1")
            .with_build(ubuntu_build(Some("2ubuntu2.13"), Some("14.04")));
        let judged = Judged::of(&service, "cpe:/a:openbsd:openssh:6.6.1p1").expect("a CPE");
        let judgement = catalogue.judge(&judged, std::slice::from_ref(&ubuntu));

        assert!(judgement.findings.is_empty(), "{:?}", kinds(&judgement));
        assert_eq!(
            judgement.withdrawn,
            Withdrawn {
                fixed: 1,
                not_affected: 1,
                elsewhere: 2
            }
        );
    }
}
