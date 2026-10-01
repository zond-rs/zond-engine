// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Ubuntu's security notices
//!
//! Turns the two archives Canonical publishes of Ubuntu's security data into
//! the [`Advisories`] the correlator judges an Ubuntu build against: the OSV
//! records, one per CVE, and the OpenVEX documents beside them. Both arrive as
//! the `.tar.xz` Canonical serves and are read as streams.
//!
//! ```no_run
//! use std::fs::File;
//!
//! let mut osv = File::open("osv-all.tar.xz")?;
//! let mut vex = File::open("vex-all.tar.xz")?;
//! let advisories = zond_engine::import::ubuntu::read(&mut osv, &mut vex)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## What each archive gives
//!
//! **OSV** (`osv/cve/**/UBUNTU-CVE-*.json`) says, for every release and
//! source package a CVE touches, whether a fix is published and at which
//! version. An entry with a `fixed` event is **fixed** from that version on,
//! and one without is **open**; OSV has no field for why, so it is open as
//! needing a fix, with Ubuntu's note on its priority where the entry carries
//! one. `Ubuntu:<release>[:LTS]` is the release's archive, and
//! `Ubuntu:Pro:<release>:LTS` its ESM pockets; the FIPS, real-time and
//! BlueField variants are dropped, because a scan cannot tell those builds
//! apart. Every version an entry lists joins the release's lineage, the CVE's
//! Ubuntu priority is kept, and the USN that published a fix is found from the
//! notices under `osv/usn/`.
//!
//! **VEX** (`vex/cve/**/CVE-*.json`) is where Ubuntu says **not affected**,
//! which OSV cannot express, with a justification and the note Ubuntu wrote
//! for the CVE. Only those statements are read, for source packages
//! (`arch=source`); a product's `distro=` qualifier names the release by
//! codename, alone for the archive or with a pocket (`esm-infra/focal`,
//! `trusty/esm`) for ESM.
//!
//! ## Fixes come from OSV
//!
//! A VEX `fixed` statement names the package version published today, which
//! is often later than the first fixed one: it lists CVE-2016-1908 on 14.04 as
//! fixed in `1:6.6p1-2ubuntu2.13+esm2`, where the fix is `1:6.6p1-2ubuntu2.7`.
//! Read as a fix version, every build between the two would be reported
//! vulnerable. OSV's `fixed` event is the first fixed version, which is what a
//! build is compared with.
//!
//! ## When the two disagree
//!
//! "Not affected" replaces an open verdict for the same release, package and
//! channel, and never a fix. OSV lists CVE-2020-14145 as open on 14.04 and
//! Ubuntu's verdict in VEX is not affected: OSV records every package a CVE
//! touches, and VEX says which of them the issue reaches.
//!
//! An OSV record Canonical has withdrawn contributes its versions to the
//! lineage and none of its verdicts, which are stale: CVE-2020-14145's
//! withdrawn record still lists 22.04 as open, where Ubuntu's verdict is not
//! affected. Without its fix, the upstream range decides, which errs toward
//! reporting a vulnerability.
//!
//! ## Filtered and streamed
//!
//! The archives are a hundred megabytes that decompress to thirty-six
//! gigabytes of JSON. They are decompressed as they are read, and an entry is
//! parsed only once a substring search of its bytes finds a source package the
//! engine's map names. Peak memory is one entry plus what survives the filter,
//! and the time is mostly decompression.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufReader, Read};
use std::path::{Component, Path};

use aho_corasick::AhoCorasick;
use serde::Deserialize;

use crate::cve::Advisories;
use crate::cve::advisories::{Builder, Channel, Distributor, OpenKind, Standing, Status};
use crate::import::{ImportError, ImportOrigin};

/// The most compressed bytes either archive may be.
///
/// Each is under a hundred megabytes; the cap stops a source that does not
/// end.
const MAX_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024;

/// The most one file in an archive may be, since each is held whole while it
/// is parsed. The largest real one is a few megabytes.
const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;

/// The longest a not-affected reason is kept, in bytes. Ubuntu's notes run to
/// paragraphs; this one sits beside a finding.
const MAX_REASON_BYTES: usize = 240;

/// Ubuntu's codenames and the release numbers they stand for, oldest first,
/// every release since the first, interim ones included.
const CODENAMES: &[(&str, &str)] = &[
    ("warty", "4.10"),
    ("hoary", "5.04"),
    ("breezy", "5.10"),
    ("dapper", "6.06"),
    ("edgy", "6.10"),
    ("feisty", "7.04"),
    ("gutsy", "7.10"),
    ("hardy", "8.04"),
    ("intrepid", "8.10"),
    ("jaunty", "9.04"),
    ("karmic", "9.10"),
    ("lucid", "10.04"),
    ("maverick", "10.10"),
    ("natty", "11.04"),
    ("oneiric", "11.10"),
    ("precise", "12.04"),
    ("quantal", "12.10"),
    ("raring", "13.04"),
    ("saucy", "13.10"),
    ("trusty", "14.04"),
    ("utopic", "14.10"),
    ("vivid", "15.04"),
    ("wily", "15.10"),
    ("xenial", "16.04"),
    ("yakkety", "16.10"),
    ("zesty", "17.04"),
    ("artful", "17.10"),
    ("bionic", "18.04"),
    ("cosmic", "18.10"),
    ("disco", "19.04"),
    ("eoan", "19.10"),
    ("focal", "20.04"),
    ("groovy", "20.10"),
    ("hirsute", "21.04"),
    ("impish", "21.10"),
    ("jammy", "22.04"),
    ("kinetic", "22.10"),
    ("lunar", "23.04"),
    ("mantic", "23.10"),
    ("noble", "24.04"),
    ("oracular", "24.10"),
    ("plucky", "25.04"),
    ("questing", "25.10"),
    ("resolute", "26.04"),
];

/// The release number an Ubuntu codename stands for.
fn release_of(codename: &str) -> Option<&'static str> {
    CODENAMES
        .iter()
        .find(|(name, _)| *name == codename)
        .map(|(_, number)| *number)
}

/// Reads Ubuntu's OSV and OpenVEX archives, as the `.tar.xz` Canonical
/// publishes them, into Ubuntu's verdicts for the source packages the engine's
/// map names.
///
/// # Errors
///
/// [`ImportError::Malformed`] for an archive or a record that is not what
/// Canonical publishes, [`ImportError::DocumentTooLarge`] for an archive or
/// an entry past its bound, and [`ImportError::Io`] where a read fails.
pub fn read(osv: &mut dyn Read, vex: &mut dyn Read) -> Result<Advisories, ImportError> {
    let wanted = Wanted::new(crate::cve::packages::source_packages("ubuntu"));
    let mut facts = Facts::default();

    each_entry(osv, "Ubuntu OSV archive", |path, bytes| {
        match path {
            ["osv", "cve", .., name]
                if is_json(name, "UBUNTU-CVE-") && wanted.osv_mentions(bytes) =>
            {
                facts.cve(&parse::<OsvRecord>(bytes, path)?, &wanted);
            }
            ["osv", "usn", .., name] if is_json(name, "USN-") && wanted.osv_mentions(bytes) => {
                facts.notice(&parse::<OsvRecord>(bytes, path)?, &wanted);
            }
            _ => {}
        }
        Ok(())
    })?;

    each_entry(vex, "Ubuntu OpenVEX archive", |path, bytes| {
        if let ["vex", "cve", .., name] = path
            && is_json(name, "CVE-")
            && wanted.vex_mentions(bytes)
        {
            let document = parse::<VexDocument>(bytes, path)?;
            facts.vex(&document, &wanted);
        }
        Ok(())
    })?;

    Ok(facts.finish())
}

/// Whether a file name is a JSON record starting with `prefix`.
fn is_json(name: &str, prefix: &str) -> bool {
    name.starts_with(prefix) && name.ends_with(".json")
}

/// Parses one archive entry, naming the entry in the error.
fn parse<'a, T: Deserialize<'a>>(bytes: &'a [u8], path: &[&str]) -> Result<T, ImportError> {
    serde_json::from_slice(bytes).map_err(|error| ImportError::Malformed {
        format: "Ubuntu security record",
        origin: ImportOrigin::line(error.line() as u64),
        message: format!("{}: {error}", path.join("/")),
    })
}

/// Walks a `.tar.xz` archive, handing each regular file's path components and
/// bytes to `visit`.
fn each_entry(
    input: &mut dyn Read,
    format: &'static str,
    mut visit: impl FnMut(&[&str], &[u8]) -> Result<(), ImportError>,
) -> Result<(), ImportError> {
    let malformed = |message: String| ImportError::Malformed {
        format,
        origin: ImportOrigin::unknown(),
        message,
    };

    let mut bounded = Read::take(input, MAX_ARCHIVE_BYTES.saturating_add(1));
    let walked = {
        let decoder = liblzma::read::XzDecoder::new(BufReader::new(&mut bounded));
        let mut archive = tar::Archive::new(decoder);
        let mut bytes = Vec::new();
        archive
            .entries()
            .map_err(|error| malformed(error.to_string()))
            .and_then(|entries| {
                for entry in entries {
                    let mut entry = entry.map_err(|error| malformed(error.to_string()))?;
                    if !entry.header().entry_type().is_file() {
                        continue;
                    }
                    let path = entry
                        .path()
                        .map_err(|error| malformed(error.to_string()))?
                        .into_owned();
                    let components = components(&path);
                    if !matches!(components.as_slice(), ["osv" | "vex", "cve" | "usn", ..]) {
                        continue;
                    }
                    if entry.size() > MAX_ENTRY_BYTES {
                        return Err(ImportError::DocumentTooLarge {
                            limit: MAX_ENTRY_BYTES,
                        });
                    }
                    bytes.clear();
                    entry
                        .read_to_end(&mut bytes)
                        .map_err(|error| malformed(format!("{}: {error}", path.display())))?;
                    visit(&components, &bytes)?;
                }
                Ok(())
            })
    };

    // At the bound, any error above was caused by the truncation.
    if bounded.limit() == 0 {
        return Err(ImportError::DocumentTooLarge {
            limit: MAX_ARCHIVE_BYTES,
        });
    }
    walked
}

/// A path's normal components as text, a leading `./` and any
/// component that is not valid UTF-8 dropped.
fn components(path: &Path) -> Vec<&str> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .collect()
}

/// The source packages kept, and a substring search for them in a record's raw
/// bytes, so a record naming none of them is not parsed.
///
/// The search may match wrongly but never misses: an OSV record names its
/// packages as JSON strings and a VEX document inside package URLs, and both
/// spellings are searched for exactly.
struct Wanted {
    names: BTreeSet<&'static str>,
    osv: AhoCorasick,
    vex: AhoCorasick,
}

impl Wanted {
    fn new(names: impl Iterator<Item = &'static str>) -> Self {
        let names: BTreeSet<&'static str> = names.collect();
        let osv = AhoCorasick::new(names.iter().map(|name| format!("\"{name}\"")))
            .expect("package names make a valid automaton");
        let vex = AhoCorasick::new(
            names
                .iter()
                .flat_map(|name| [format!("/{name}@"), format!("\\/{name}@")]),
        )
        .expect("package names make a valid automaton");
        Self { names, osv, vex }
    }

    fn contains(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    fn osv_mentions(&self, bytes: &[u8]) -> bool {
        self.osv.is_match(bytes)
    }

    fn vex_mentions(&self, bytes: &[u8]) -> bool {
        self.vex.is_match(bytes)
    }
}

/// One OSV record, a CVE's or a notice's, cut down to what is read.
#[derive(Deserialize)]
struct OsvRecord {
    id: String,
    #[serde(default)]
    modified: Option<String>,
    #[serde(default)]
    withdrawn: Option<String>,
    #[serde(default)]
    upstream: Vec<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

/// One of a record's severity ratings; the one typed `Ubuntu` is the
/// priority Ubuntu gives the CVE.
#[derive(Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

/// One source package in one release or variant, with its fix events and
/// the versions it has had.
#[derive(Deserialize)]
struct OsvAffected {
    package: OsvPackage,
    #[serde(default)]
    ranges: Vec<OsvRange>,
    #[serde(default)]
    versions: Vec<String>,
    #[serde(default)]
    ecosystem_specific: Option<OsvSpecific>,
}

impl OsvAffected {
    /// The fixed events across its ranges.
    fn fixes(&self) -> impl Iterator<Item = &str> {
        self.ranges
            .iter()
            .flat_map(|range| &range.events)
            .filter_map(|event| event.get("fixed"))
            .map(String::as_str)
    }
}

/// The package an entry concerns and the ecosystem naming its release.
#[derive(Deserialize)]
struct OsvPackage {
    ecosystem: String,
    name: String,
}

/// A version range, as the events that open and close it.
#[derive(Deserialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<BTreeMap<String, String>>,
}

/// Ubuntu's own fields on an entry: a per-package priority and the note
/// explaining a priority.
#[derive(Deserialize)]
struct OsvSpecific {
    #[serde(default)]
    ubuntu_priority: Option<String>,
    #[serde(default)]
    priority_reason: Option<String>,
}

/// The release and channel an OSV ecosystem names, or nothing for the
/// variants a scan cannot tell apart.
///
/// `Ubuntu:14.04:LTS` and `Ubuntu:25.10` are archives, `Ubuntu:Pro:14.04:LTS`
/// ESM. Everything else, `Ubuntu:Pro:FIPS:…`, `Ubuntu:Pro:Realtime:…`, the
/// BlueField builds, is a variant.
fn ecosystem(ecosystem: &str) -> Option<(&str, Channel)> {
    let release = |text: &str| {
        let (major, minor) = text.split_once('.')?;
        let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
        (digits(major) && digits(minor)).then_some(())
    };
    let parts: Vec<&str> = ecosystem.split(':').collect();
    let (number, channel) = match parts.as_slice() {
        ["Ubuntu", number] | ["Ubuntu", number, "LTS"] => (*number, Channel::Archive),
        ["Ubuntu", "Pro", number, "LTS"] => (*number, Channel::Esm),
        _ => return None,
    };
    release(number)?;
    Some((number, channel))
}

/// A notice id's numbers, `USN-6242-2` as `(6242, 2)`, so the original
/// notice sorts before its follow-ups.
fn notice_order(id: &str) -> Option<(u32, u32)> {
    let (number, revision) = id.strip_prefix("USN-")?.split_once('-')?;
    Some((number.parse().ok()?, revision.parse().ok()?))
}

/// One OSV fix, held until every notice has been read.
struct Fix {
    release: String,
    package: String,
    cve: String,
    channel: Channel,
    version: String,
}

/// What the archives say, gathered while they stream.
///
/// Fixes are held until the end, because the notice that published one may be
/// in a later file.
#[derive(Default)]
struct Facts {
    builder: Option<Builder>,
    fixes: Vec<Fix>,
    /// The first notice to publish each fix: release, channel, package and
    /// version to the notice's id.
    notices: BTreeMap<(String, Channel, String, String), String>,
}

impl Facts {
    fn builder(&mut self) -> &mut Builder {
        self.builder
            .get_or_insert_with(|| Builder::new(Distributor::Ubuntu))
    }

    /// One CVE's OSV record.
    fn cve(&mut self, record: &OsvRecord, wanted: &Wanted) {
        let Some(cve) = record
            .upstream
            .iter()
            .map(String::as_str)
            .find(|id| id.starts_with("CVE-"))
            .or_else(|| record.id.strip_prefix("UBUNTU-"))
            .filter(|id| id.starts_with("CVE-"))
        else {
            return;
        };
        let builder = self
            .builder
            .get_or_insert_with(|| Builder::new(Distributor::Ubuntu));
        if let Some(modified) = &record.modified {
            builder.dated(modified);
        }
        if let Some(priority) = record.severity.iter().find(|s| s.kind == "Ubuntu") {
            builder.priority(None, cve, &priority.score);
        }

        for affected in &record.affected {
            let package = affected.package.name.as_str();
            if !wanted.contains(package) {
                continue;
            }
            let Some((release, channel)) = ecosystem(&affected.package.ecosystem) else {
                continue;
            };
            builder.versions(
                release,
                package,
                affected.versions.iter().map(String::as_str),
            );
            let specific = affected.ecosystem_specific.as_ref();
            if let Some(priority) = specific.and_then(|s| s.ubuntu_priority.as_deref()) {
                builder.priority(Some(release), cve, priority);
            }
            if record.withdrawn.is_some() {
                continue;
            }

            let mut fixed = false;
            for version in affected.fixes() {
                fixed = true;
                self.fixes.push(Fix {
                    release: release.to_string(),
                    package: package.to_string(),
                    cve: cve.to_string(),
                    channel,
                    version: version.to_string(),
                });
            }
            if !fixed {
                let note = specific
                    .and_then(|s| s.priority_reason.as_deref())
                    .filter(|note| !note.is_empty())
                    .map(str::to_string);
                let status = Status {
                    channel,
                    standing: Standing::Open {
                        kind: OpenKind::Needed,
                        note,
                    },
                    advisory: None,
                };
                builder.record(release, package, cve, status);
            }
        }
    }

    /// One notice's OSV record: which fixes it published.
    fn notice(&mut self, record: &OsvRecord, wanted: &Wanted) {
        let Some(order) = notice_order(&record.id) else {
            return;
        };
        if let Some(modified) = &record.modified {
            self.builder().dated(modified);
        }
        for affected in &record.affected {
            let package = affected.package.name.as_str();
            if !wanted.contains(package) {
                continue;
            }
            let Some((release, channel)) = ecosystem(&affected.package.ecosystem) else {
                continue;
            };
            for version in affected.fixes() {
                let key = (
                    release.to_string(),
                    channel,
                    package.to_string(),
                    version.to_string(),
                );
                let held = self.notices.entry(key).or_insert_with(|| record.id.clone());
                if notice_order(held).is_none_or(|held| order < held) {
                    held.clone_from(&record.id);
                }
            }
        }
    }

    /// One CVE's VEX document: its not-affected statements.
    fn vex(&mut self, document: &VexDocument, wanted: &Wanted) {
        let builder = self.builder();
        if let Some(timestamp) = &document.timestamp {
            builder.dated(timestamp);
        }
        for statement in &document.statements {
            if statement.status != "not_affected" {
                continue;
            }
            let cve = statement.vulnerability.name.as_str();
            if !cve.starts_with("CVE-") {
                continue;
            }
            let reason = reason(
                statement.justification.as_deref(),
                statement.impact_statement.as_deref(),
            );
            for product in &statement.products {
                let Some(product) = Purl::parse(&product.id) else {
                    continue;
                };
                if !product.source || !wanted.contains(product.name) {
                    continue;
                }
                let Some((release, channel)) = product.release else {
                    continue;
                };
                builder.versions(release, product.name, [product.version]);
                let status = Status {
                    channel,
                    standing: Standing::NotAffected {
                        reason: reason.clone(),
                    },
                    advisory: None,
                };
                builder.record(release, product.name, cve, status);
            }
        }
    }

    fn finish(mut self) -> Advisories {
        let fixes = std::mem::take(&mut self.fixes);
        for fix in fixes {
            let key = (fix.release, fix.channel, fix.package, fix.version);
            let advisory = self.notices.get(&key).cloned();
            let (release, channel, package, version) = key;
            let status = Status {
                channel,
                standing: Standing::Fixed { version },
                advisory,
            };
            self.builder().record(&release, &package, &fix.cve, status);
        }
        self.builder
            .unwrap_or_else(|| Builder::new(Distributor::Ubuntu))
            .finish()
    }
}

/// A not-affected reason: the justification in words, then Ubuntu's note on
/// the CVE, cut to its first two sentences and a length that fits beside a
/// finding.
fn reason(justification: Option<&str>, impact: Option<&str>) -> Option<String> {
    let justification = justification
        .filter(|text| !text.is_empty())
        .map(|text| text.replace('_', " "));
    let note = impact
        .and_then(|text| text.split_once("CVE Notes / justification:"))
        .map(|(_, note)| first_sentences(note.trim(), 2))
        .filter(|note| !note.is_empty());
    let reason = match (justification, note) {
        (Some(justification), Some(note)) => format!("{justification}: {note}"),
        (Some(text), None) | (None, Some(text)) => text,
        (None, None) => return None,
    };
    Some(cut(&reason, MAX_REASON_BYTES))
}

/// The first `count` sentences of `text`, a sentence ending at a full stop
/// followed by a space.
fn first_sentences(text: &str, count: usize) -> String {
    let mut end = text.len();
    let mut seen = 0;
    for (at, _) in text.match_indices(". ") {
        seen += 1;
        if seen == count {
            end = at + 1;
            break;
        }
    }
    text[..end].trim().to_string()
}

/// `text` cut to at most `limit` bytes on a character boundary, with an
/// ellipsis where anything was cut.
fn cut(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }
    let mut end = limit - '…'.len_utf8();
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", text[..end].trim_end())
}

/// One CVE's OpenVEX document, cut down to what is read.
#[derive(Deserialize)]
struct VexDocument {
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    statements: Vec<VexStatement>,
}

/// One statement: a status on a CVE for a list of products, with the
/// justification and note a not-affected one carries.
#[derive(Deserialize)]
struct VexStatement {
    vulnerability: VexVulnerability,
    status: String,
    #[serde(default)]
    products: Vec<VexProduct>,
    #[serde(default)]
    justification: Option<String>,
    #[serde(default)]
    impact_statement: Option<String>,
}

/// The CVE a statement is about.
#[derive(Deserialize)]
struct VexVulnerability {
    name: String,
}

/// One product a statement covers, as a package URL.
#[derive(Deserialize)]
struct VexProduct {
    #[serde(rename = "@id")]
    id: String,
}

/// A VEX product's package URL, `pkg:deb/ubuntu/<name>@<version>?<qualifiers>`.
struct Purl<'a> {
    name: &'a str,
    version: &'a str,
    /// Whether it names a source package (`arch=source`).
    source: bool,
    /// The release and channel its `distro=` names, or nothing for one that
    /// names a variant or a codename this table does not know.
    release: Option<(&'static str, Channel)>,
}

impl<'a> Purl<'a> {
    fn parse(purl: &'a str) -> Option<Self> {
        let rest = purl.strip_prefix("pkg:deb/ubuntu/")?;
        let (package, qualifiers) = rest.split_once('?').unwrap_or((rest, ""));
        let (name, version) = package.split_once('@')?;
        let mut source = false;
        let mut release = None;
        for qualifier in qualifiers.split('&') {
            match qualifier.split_once('=') {
                Some(("arch", arch)) => source = arch == "source",
                Some(("distro", distro)) => release = distro_release(distro),
                _ => {}
            }
        }
        Some(Self {
            name,
            version,
            source,
            release,
        })
    }
}

/// The release and channel a `distro=` qualifier names: a codename alone for
/// the archive, or with a pocket on either side of it. `esm`, `esm-infra`,
/// `esm-apps` and their `-legacy` forms are ESM; FIPS, real-time and BlueField
/// pockets are variants and name nothing here.
fn distro_release(distro: &str) -> Option<(&'static str, Channel)> {
    let (codename, pocket) = match distro.split_once('/') {
        None => (distro, None),
        Some((first, second)) => match release_of(first) {
            Some(_) => (first, Some(second)),
            None => (second, Some(first)),
        },
    };
    let release = release_of(codename)?;
    match pocket {
        None => Some((release, Channel::Archive)),
        Some(pocket) if pocket.starts_with("esm") => Some((release, Channel::Esm)),
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trimmed excerpt of each archive: the `openssh` records the
    /// acceptance cases name and the notices that published their fixes, a
    /// neighbour naming no mapped package, and the VEX documents for the
    /// same CVEs plus one that names the one codename they do not.
    const OSV: &[u8] = include_bytes!("../../tests/data/distro/ubuntu-osv.tar.xz");
    const VEX: &[u8] = include_bytes!("../../tests/data/distro/ubuntu-vex.tar.xz");

    fn read_fixture() -> Advisories {
        read(&mut &OSV[..], &mut &VEX[..]).expect("the fixture converts")
    }

    fn fixed(channel: Channel, version: &str, advisory: Option<&str>) -> Status {
        Status {
            channel,
            standing: Standing::Fixed {
                version: version.to_string(),
            },
            advisory: advisory.map(str::to_string),
        }
    }

    /// The fix versions are OSV's first fixed versions, carried by the
    /// notice that published them.
    #[test]
    fn a_fix_is_the_first_fixed_version_with_its_notice() {
        let data = read_fixture();
        assert_eq!(
            data.statuses("14.04", "openssh", "CVE-2016-1908"),
            &[fixed(
                Channel::Archive,
                "1:6.6p1-2ubuntu2.7",
                Some("USN-2966-1")
            )]
        );
        assert_eq!(
            data.statuses("14.04", "openssh", "CVE-2015-5600"),
            &[fixed(
                Channel::Archive,
                "1:6.6p1-2ubuntu2.2",
                Some("USN-2710-1")
            )]
        );
        assert_eq!(data.id(), "ubuntu:security-notices");
    }

    /// A fix published only to ESM is recorded for the ESM channel alone.
    #[test]
    fn an_esm_fix_is_not_an_archive_fix() {
        let data = read_fixture();
        let statuses = data.statuses("14.04", "openssh", "CVE-2023-38408");
        assert_eq!(
            statuses,
            &[fixed(
                Channel::Esm,
                "1:6.6p1-2ubuntu2.13+esm1",
                Some("USN-6242-2")
            )]
        );
        assert!(
            !statuses
                .iter()
                .any(|status| status.channel == Channel::Archive
                    && matches!(status.standing, Standing::Fixed { .. }))
        );
    }

    /// Not affected comes from VEX, including where OSV lists the CVE as
    /// open, and it carries Ubuntu's reason.
    #[test]
    fn not_affected_comes_from_vex_and_overrides_an_open_verdict() {
        let data = read_fixture();
        for cve in ["CVE-2016-10010", "CVE-2020-14145"] {
            let statuses = data.statuses("14.04", "openssh", cve);
            assert!(
                matches!(
                    statuses,
                    [Status {
                        channel: Channel::Esm,
                        standing: Standing::NotAffected { reason: Some(_) },
                        ..
                    }]
                ),
                "{cve}: {statuses:?}"
            );
        }
        let [
            Status {
                standing:
                    Standing::NotAffected {
                        reason: Some(reason),
                    },
                ..
            },
        ] = data.statuses("14.04", "openssh", "CVE-2016-10010")
        else {
            unreachable!("matched above");
        };
        assert!(
            reason.starts_with("vulnerable code not present: "),
            "{reason}"
        );
        assert!(reason.len() <= MAX_REASON_BYTES, "{reason}");
    }

    /// VEX's fixed statements are not read as fixes: for CVE-2016-1908 on
    /// 14.04 it names a much later build than the one that fixed it.
    #[test]
    fn a_vex_fixed_statement_is_not_a_fix_version() {
        let data = read_fixture();
        let statuses = data.statuses("14.04", "openssh", "CVE-2016-1908");
        assert!(
            !statuses.iter().any(|status| matches!(
                &status.standing,
                Standing::Fixed { version } if version.contains("+esm")
            )),
            "{statuses:?}"
        );
    }

    /// An entry with no fixed event is open, with Ubuntu's note.
    #[test]
    fn an_entry_without_a_fix_is_open() {
        let data = read_fixture();
        let statuses = data.statuses("14.04", "openssh", "CVE-2021-41617");
        assert!(
            matches!(
                statuses,
                [Status {
                    channel: Channel::Esm,
                    standing: Standing::Open {
                        kind: OpenKind::Needed,
                        note: Some(_),
                    },
                    ..
                }]
            ),
            "{statuses:?}"
        );
    }

    /// A withdrawn record's verdicts are not read: its fix for CVE-2016-1907
    /// is not taken, and 22.04 keeps only VEX's not affected for
    /// CVE-2020-14145.
    #[test]
    fn a_withdrawn_record_gives_no_verdicts() {
        let data = read_fixture();
        let statuses = data.statuses("14.04", "openssh", "CVE-2016-1907");
        assert!(
            !statuses
                .iter()
                .any(|status| matches!(status.standing, Standing::Fixed { .. })),
            "{statuses:?}"
        );
        let statuses = data.statuses("22.04", "openssh", "CVE-2020-14145");
        assert!(
            matches!(
                statuses,
                [Status {
                    channel: Channel::Archive,
                    standing: Standing::NotAffected { .. },
                    ..
                }]
            ),
            "{statuses:?}"
        );
    }

    /// FIPS and other variant builds are dropped, from OSV and from VEX.
    #[test]
    fn variant_builds_are_dropped() {
        let data = read_fixture();
        for release in ["16.04", "18.04", "20.04"] {
            let statuses = data.statuses(release, "openssh", "CVE-2023-38408");
            assert!(
                statuses.iter().all(|status| match &status.standing {
                    Standing::Fixed { version } => !version.contains("fips"),
                    _ => true,
                }),
                "{release}: {statuses:?}"
            );
        }
        let lineage = data.lineage("16.04", "openssh").expect("a lineage");
        assert!(
            lineage.versions().iter().all(|v| !v.contains("fips")),
            "{lineage:?}"
        );
    }

    /// The versions OSV lists join the lineage, and the priority is kept.
    #[test]
    fn versions_and_priority_are_kept() {
        let data = read_fixture();
        let lineage = data.lineage("14.04", "openssh").expect("a lineage");
        for version in [
            "1:6.6p1-2ubuntu2",
            "1:6.6p1-2ubuntu2.13",
            "1:6.6p1-2ubuntu2.13+esm1",
        ] {
            assert!(
                lineage.versions().iter().any(|v| v == version),
                "{version} in {lineage:?}"
            );
        }
        assert_eq!(
            data.priority(Some("14.04"), "CVE-2023-38408"),
            Some("medium")
        );
        assert!(data.version() > crate::model::finding::Version::new(2026, 1, 1));
    }

    /// Packages outside the map are dropped, even beside one that is kept.
    #[test]
    fn only_mapped_packages_are_kept() {
        let data = read_fixture();
        assert!(data.lineage("18.04", "openssh-ssh1").is_none());
        assert!(
            data.statuses("22.04", "openssh-ssh1", "CVE-2023-38408")
                .is_empty()
        );
    }

    /// Every codename the fixture's VEX products name maps to a release, and
    /// the fixture spans every one the whole archive used when it was cut.
    #[test]
    fn every_codename_in_the_archive_maps_to_a_release() {
        let today = [
            "trusty", "xenial", "bionic", "focal", "jammy", "noble", "plucky", "questing",
            "resolute",
        ];
        for codename in today {
            assert!(release_of(codename).is_some(), "{codename}");
        }

        let mut seen = BTreeSet::new();
        each_entry(&mut &VEX[..], "test", |_, bytes| {
            let text = std::str::from_utf8(bytes).expect("UTF-8");
            for (at, _) in text.match_indices("distro=") {
                let distro: String = text[at + 7..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || "/-".contains(*c))
                    .collect();
                seen.insert(distro);
            }
            Ok(())
        })
        .expect("the fixture walks");
        let codenames: BTreeSet<&str> = seen
            .iter()
            .flat_map(|distro| distro.split('/'))
            .filter(|part| release_of(part).is_some())
            .collect();
        assert_eq!(codenames, BTreeSet::from(today), "{seen:?}");
        for distro in &seen {
            assert!(
                distro.split('/').any(|part| release_of(part).is_some()),
                "{distro} names no known codename"
            );
        }
    }

    /// Ecosystems and pockets map to channels, and the variants to nothing.
    #[test]
    fn ecosystems_and_pockets_name_a_release_and_channel() {
        assert_eq!(
            ecosystem("Ubuntu:14.04:LTS"),
            Some(("14.04", Channel::Archive))
        );
        assert_eq!(ecosystem("Ubuntu:25.10"), Some(("25.10", Channel::Archive)));
        assert_eq!(
            ecosystem("Ubuntu:Pro:14.04:LTS"),
            Some(("14.04", Channel::Esm))
        );
        for variant in [
            "Ubuntu:Pro:FIPS:16.04:LTS",
            "Ubuntu:Pro:FIPS-updates:18.04:LTS",
            "Ubuntu:Pro:Realtime:22.04:LTS",
            "Ubuntu:Pro:22.04:LTS:Realtime:Kernel",
            "Ubuntu:Nvidia-BlueField:22.04:LTS",
            "Ubuntu:22.04:LTS:for:NVIDIA:BlueField",
            "Debian:12",
        ] {
            assert_eq!(ecosystem(variant), None, "{variant}");
        }

        assert_eq!(distro_release("trusty"), Some(("14.04", Channel::Archive)));
        assert_eq!(distro_release("trusty/esm"), Some(("14.04", Channel::Esm)));
        assert_eq!(
            distro_release("esm-infra-legacy/trusty"),
            Some(("14.04", Channel::Esm))
        );
        assert_eq!(
            distro_release("esm-apps/noble"),
            Some(("24.04", Channel::Esm))
        );
        for variant in [
            "fips/xenial",
            "fips-updates/jammy",
            "realtime/noble",
            "bluefield/jammy",
        ] {
            assert_eq!(distro_release(variant), None, "{variant}");
        }
    }

    /// A reason is the justification and the first sentences of the note,
    /// within the length a note beside a finding may be.
    #[test]
    fn a_reason_is_short_and_says_why() {
        let long = format!(
            "Boilerplate. CVE Notes / justification: One. Two. Three. {}",
            "x".repeat(500)
        );
        assert_eq!(
            reason(Some("vulnerable_code_not_present"), Some(&long)).as_deref(),
            Some("vulnerable code not present: One. Two.")
        );
        let unbroken = format!("CVE Notes / justification: {}", "é".repeat(400));
        let cut = reason(None, Some(&unbroken)).expect("a reason");
        assert!(cut.len() <= MAX_REASON_BYTES && cut.ends_with('…'), "{cut}");
        assert_eq!(reason(None, Some("no notes here")), None);
    }

    /// Where several notices publish one fix, as a notice and its follow-up
    /// do, the original is named, whichever the archive holds first.
    #[test]
    fn the_first_notice_to_publish_a_fix_is_named() {
        let notice = |id: &str| -> OsvRecord {
            serde_json::from_str(&format!(
                r#"{{"id": "{id}", "affected": [{{
                    "package": {{"ecosystem": "Ubuntu:20.04:LTS", "name": "openssh"}},
                    "ranges": [{{"type": "ECOSYSTEM",
                        "events": [{{"introduced": "0"}}, {{"fixed": "1:8.2p1-4ubuntu0.8"}}]}}]
                }}]}}"#
            ))
            .expect("a notice")
        };
        let cve: OsvRecord = serde_json::from_str(
            r#"{"id": "UBUNTU-CVE-2023-38408", "upstream": ["CVE-2023-38408"], "affected": [{
                "package": {"ecosystem": "Ubuntu:20.04:LTS", "name": "openssh"},
                "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "1:8.2p1-4ubuntu0.8"}]}]
            }]}"#,
        )
        .expect("a record");
        let wanted = Wanted::new(["openssh"].into_iter());

        for order in [["USN-6242-2", "USN-6242-1"], ["USN-6242-1", "USN-6242-2"]] {
            let mut facts = Facts::default();
            for id in order {
                facts.notice(&notice(id), &wanted);
            }
            facts.cve(&cve, &wanted);
            let data = facts.finish();
            assert_eq!(
                data.statuses("20.04", "openssh", "CVE-2023-38408"),
                &[fixed(
                    Channel::Archive,
                    "1:8.2p1-4ubuntu0.8",
                    Some("USN-6242-1")
                )],
                "{order:?}"
            );
        }
    }

    /// An archive that is not one is refused as malformed.
    #[test]
    fn an_archive_that_is_not_one_is_malformed() {
        let result = read(&mut &b"not an archive"[..], &mut &VEX[..]);
        assert!(
            matches!(result, Err(ImportError::Malformed { .. })),
            "{result:?}"
        );
    }
}
