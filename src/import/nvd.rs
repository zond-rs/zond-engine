// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The National Vulnerability Database feed
//!
//! Turns a year of NVD's JSON into a [`Catalogue`] the correlator can use, the
//! way [`kev`](super::kev) turns CISA's feed into one. The difference between
//! the two is versions, and versions are most of what a catalogue is worth: a
//! KEV entry names a vendor and a product and stops, where an NVD record carries
//! the CPE ranges a vulnerability applies to. That is the difference between
//! *this host runs Exim, go and look* and *this host runs Exim 4.90, which is in
//! the affected range*.
//!
//! ```no_run
//! use std::fs::File;
//! use std::io::BufReader;
//!
//! let file = File::open("CVE-2024.json")?;
//! let catalogue = zond_engine::import::nvd::read(&mut BufReader::new(file))?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Where the bytes come from
//!
//! NVD retired its own JSON feeds at the end of 2023 in favour of a rate-limited
//! REST API, so the shape this reads is the one the community reconstruction
//! publishes: an object carrying a `timestamp` and a `cve_items` array. The
//! same records come back from the 2.0 API a page at a time, and a caller who
//! assembles those pages into that shape is read here unchanged.
//!
//! ## It filters, and [`kev`](super::kev) does not
//!
//! A converted KEV holds every entry CISA published, because there are about
//! twelve hundred of them and the correlator ignoring most is free. NVD is three
//! hundred and eighty thousand records naming several hundred thousand distinct
//! products, and converting all of it would produce a document larger than
//! [`MAX_DOCUMENT_BYTES`] by two orders of magnitude before anything could read
//! it back.
//!
//! So the corpus decides. [`SignatureDb::versioned_products`] is every
//! `vendor:product` a scan can name *with a version*, and a record naming
//! anything else is dropped as it goes past. Nothing is lost that could have
//! been found: an entry for software the fingerprint corpus cannot put a version
//! to has nothing to match against, in exactly the sense the context register
//! means by [`Reach::Unproduced`](crate::fingerprint::Reach).
//!
//! Two hundred and sixty-nine products are named by some rule and never with a
//! version. Those are the ones this drops and KEV would keep, and keeping them
//! would be a megabyte of entries that cannot fire.
//!
//! ## Applications, not operating systems
//!
//! An `o:` CPE's version is a release family — `microsoft:windows_server_2016`,
//! `linux:linux_kernel` — and a scan does not read a kernel's patch level off
//! the wire. A catalogue entry keyed there fires on every host of that family
//! and can be neither confirmed nor denied by anything a scan can see, which is
//! worse than saying nothing. `linux:linux_kernel` alone accounts for eighteen
//! thousand CPE matches in a single year of the feed.
//!
//! The honest version of that claim is the one KEV already makes: *this host
//! runs software with known vulnerabilities, go and check*, recorded at
//! [`Confidence::Weak`](crate::model::confidence::Confidence::Weak). Convert
//! KEV for it. This reader keeps `a:` records and leaves `o:` alone.
//!
//! ## One record at a time
//!
//! [`kev`](super::kev) reads its whole input into a string, which is right for a
//! feed of a few megabytes. A year of NVD is three hundred, so this one streams:
//! the array is walked element by element and each record is converted and
//! dropped before the next is read. Peak memory is one record plus whatever
//! survived the filter, not the size of the input.
//!
//! ## A record becomes more than one entry
//!
//! The catalogue's `affected` grammar is a comma-joined *conjunction*: every
//! clause must hold. A vulnerability with disjoint ranges cannot be written as
//! one, and they are common — CVE-2024-6387 affects OpenSSH below 4.4 *and*
//! from 8.5 to 9.8, which is two claims rather than one. Each range becomes its
//! own entry under the same CVE id, and a record naming several products becomes
//! one entry per product.

use std::collections::BTreeSet;
use std::fmt;
use std::io::BufRead;

use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::cve::{Catalogue, CatalogueError, MAX_DOCUMENT_BYTES};
use crate::fingerprint::SignatureDb;

/// What a converted catalogue names itself.
///
/// NVD's, not this engine's. The `zond:` namespace is what this crate ships and
/// is refused to anything read from outside; a converted feed is somebody else's
/// data passing through, and a report saying so is a report a reader can trace.
pub const NVD_ID: &str = "nvd:cve";

/// The most of a feed this will read.
///
/// A hundred times [`MAX_DOCUMENT_BYTES`], because the input and the output are
/// not the same size here and the ratio is the whole point: a year of NVD is
/// three hundred megabytes and converts to a few hundred kilobytes. The cap is
/// still a cap — a source with no end must not be read until the process runs
/// out of memory to discover it had none — and the streaming below means it is
/// never all held at once.
pub const MAX_FEED_BYTES: u64 = 100 * MAX_DOCUMENT_BYTES;

/// The longest `title` an entry carries.
///
/// An NVD description is a paragraph and a catalogue title is a label, so the
/// first sentence is taken and cut here if it is still long. Titles are just
/// under half of a converted document's bytes, and a title nobody can read at a
/// glance is not doing the job a title is for.
const MAX_TITLE_BYTES: usize = 160;

/// Why an NVD feed could not be converted.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum NvdError {
    /// The bytes could not be read.
    #[error("the NVD feed could not be read: {0}")]
    Io(#[from] std::io::Error),

    /// The document is not the JSON this feed publishes.
    #[error("the NVD feed is malformed: {0}")]
    Malformed(String),

    /// The feed was longer than [`MAX_FEED_BYTES`].
    #[error("the NVD feed is longer than the {limit} byte limit")]
    TooLarge {
        /// The limit it passed.
        limit: u64,
    },

    /// More of the feed survived the filter than a catalogue document may hold.
    ///
    /// Not a malformed feed and not an oversized one: a legitimate conversion
    /// whose result is too large to read back. It carries the count so a caller
    /// can see how far past the line it went, and the answer is to convert one
    /// year at a time rather than the whole history at once.
    #[error("{entries} entries convert to more than the {limit} byte document limit")]
    TooManyEntries {
        /// How many entries were kept.
        entries: usize,
        /// The document limit they did not fit in.
        limit: u64,
    },

    /// The converted document was refused by the catalogue reader, which is a
    /// defect in the conversion rather than in the feed.
    #[error("the converted catalogue was refused: {0}")]
    Rejected(#[from] CatalogueError),
}

/// Converts the NVD JSON in `input` into the TOML document
/// [`Catalogue::read`] consumes.
///
/// The result names itself [`NVD_ID`] and carries the feed's own `timestamp`, so
/// two scans run against two dumps of the feed are visibly different in the
/// report.
///
/// Filtered against the shipped fingerprint corpus; see the module documentation
/// for what that drops and why nothing is lost by it.
///
/// # Errors
///
/// [`NvdError::Malformed`] for JSON that is not this feed,
/// [`NvdError::TooLarge`] past [`MAX_FEED_BYTES`], and
/// [`NvdError::TooManyEntries`] where what survived the filter will not fit in a
/// catalogue document.
pub fn to_document(input: &mut dyn BufRead) -> Result<String, NvdError> {
    to_document_for(input, SignatureDb::global().versioned_products())
}

/// [`to_document`], against a stated set of `vendor:product` keys rather than
/// the shipped corpus's.
///
/// Exposed for a caller who fingerprints with a corpus of their own, and for
/// tests, which need a filter that does not move when the corpus does.
///
/// # Errors
///
/// The same as [`to_document`].
pub fn to_document_for(
    input: &mut dyn BufRead,
    products: &BTreeSet<String>,
) -> Result<String, NvdError> {
    // Bounded at the reader rather than after the fact: `Read::take` is what
    // makes an endless source finite, and the streaming deserializer below never
    // holds more than one record of what it yields.
    let bounded = std::io::Read::take(input, MAX_FEED_BYTES.saturating_add(1));
    let counted = Counting::new(bounded);
    let read = counted.read.clone();

    let mut deserializer = serde_json::Deserializer::from_reader(counted);
    let feed = Feed { products }
        .deserialize(&mut deserializer)
        .map_err(|error| NvdError::Malformed(error.to_string()))?;

    if read.get() > MAX_FEED_BYTES {
        return Err(NvdError::TooLarge {
            limit: MAX_FEED_BYTES,
        });
    }

    let document = Document {
        id: NVD_ID.to_string(),
        version: feed_version(&feed.timestamp),
        vulnerability: feed.vulnerability,
    };

    // Serialised rather than written by hand. Every string here is NVD's, and a
    // description carrying a quote or a backslash would end a hand-written
    // document early or change what came after it.
    let toml =
        toml::to_string(&document).map_err(|error| NvdError::Malformed(error.to_string()))?;

    if toml.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(NvdError::TooManyEntries {
            entries: document.vulnerability.len(),
            limit: MAX_DOCUMENT_BYTES,
        });
    }
    Ok(toml)
}

/// Reads the NVD JSON in `input` as a [`Catalogue`].
///
/// [`to_document`] and [`Catalogue::read`] in sequence, which is the ordinary
/// call. Convert once with [`to_document`] and keep the result where a scan is
/// re-run against the same feed: the conversion reads several hundred megabytes
/// and the document it produces is a few hundred kilobytes.
///
/// # Errors
///
/// Everything [`to_document`] returns, and [`NvdError::Rejected`] where the
/// document it produced was refused.
pub fn read(input: &mut dyn BufRead) -> Result<Catalogue, NvdError> {
    let document = to_document(input)?;
    Ok(Catalogue::read(&mut document.as_bytes())?)
}

/// The feed's `timestamp` as the catalogue grammar's `major.minor.patch`.
///
/// The feed writes an ISO instant, `2026-09-08T00:00:09+00:00`, whose date is
/// already the three components a version wants once the leading zeros are gone.
/// Anything else is carried as `0.0.0`, which is a version that sorts below
/// every real one and says plainly that the feed did not date itself.
fn feed_version(timestamp: &str) -> String {
    let date = timestamp.split('T').next().unwrap_or_default();
    let mut parts = date.split('-');

    let mut number = || -> Option<u32> { parts.next()?.parse().ok() };
    match (number(), number(), number()) {
        (Some(year), Some(month), Some(day)) => format!("{year}.{month}.{day}"),
        _ => "0.0.0".to_string(),
    }
}

/// A reader that remembers how much went through it.
///
/// `Read::take` stops at the limit without saying whether it was reached, and a
/// feed truncated exactly at the cap would otherwise be reported as malformed
/// JSON rather than as too large. The count is what tells those apart.
struct Counting<R> {
    inner: R,
    read: std::rc::Rc<std::cell::Cell<u64>>,
}

impl<R> Counting<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            read: std::rc::Rc::new(std::cell::Cell::new(0)),
        }
    }
}

impl<R: std::io::Read> std::io::Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read.set(self.read.get().saturating_add(n as u64));
        Ok(n)
    }
}

/// The whole feed, deserialized against a filter.
///
/// A seed rather than a plain `Deserialize` because the filter has to be in hand
/// *while* the array is walked: it is what decides whether a record is kept, and
/// deciding afterwards would mean holding all of them.
struct Feed<'a> {
    products: &'a BTreeSet<String>,
}

/// What survived it.
struct Converted {
    timestamp: String,
    vulnerability: Vec<Entry>,
}

impl<'de> DeserializeSeed<'de> for Feed<'_> {
    type Value = Converted;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Converted, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Feed<'_> {
    type Value = Converted;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an NVD feed object carrying `cve_items`")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Converted, A::Error> {
        let mut timestamp = String::new();
        let mut vulnerability = Vec::new();
        let mut seen_items = false;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "timestamp" => timestamp = map.next_value()?,
                "cve_items" | "vulnerabilities" => {
                    seen_items = true;
                    vulnerability = map.next_value_seed(Records {
                        products: self.products,
                    })?;
                }
                // Every other key is read and thrown away rather than refused:
                // this feed grows fields, and a reader that fails on one it has
                // not been told about fails on next year's data.
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }

        if !seen_items {
            return Err(serde::de::Error::missing_field("cve_items"));
        }
        Ok(Converted {
            timestamp,
            vulnerability,
        })
    }
}

/// The `cve_items` array, converted as it is walked.
struct Records<'a> {
    products: &'a BTreeSet<String>,
}

impl<'de> DeserializeSeed<'de> for Records<'_> {
    type Value = Vec<Entry>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Vec<Entry>, D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for Records<'_> {
    type Value = Vec<Entry>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an array of NVD records")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<Entry>, A::Error> {
        let mut out = Vec::new();
        // One record in hand at a time. It is converted to however many entries
        // it yields and then dropped, which is what keeps a three-hundred
        // megabyte feed off the heap.
        while let Some(record) = seq.next_element::<Record>()? {
            entries_from(&record, self.products, &mut out);
        }
        Ok(out)
    }
}

/// One NVD record, cut down to what a catalogue entry needs.
///
/// The 2.0 API nests the record under a `cve` key and the reconstructed feed
/// does not, so both shapes arrive here. `#[serde(default)]` throughout because
/// a record is allowed to carry none of this: one with no severity or no
/// configuration is simply not convertible, and that is decided in
/// [`entries_from`] rather than by refusing to parse.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    /// Present on the 2.0 API's shape, absent on the feed's, and the reason this
    /// is one type rather than two.
    cve: Option<Box<Record>>,
    #[serde(default)]
    id: String,
    #[serde(default)]
    vuln_status: String,
    #[serde(default)]
    descriptions: Vec<Description>,
    #[serde(default)]
    metrics: Metrics,
    #[serde(default)]
    weaknesses: Vec<Weakness>,
    #[serde(default)]
    configurations: Vec<Configuration>,
}

/// One human-readable string the feed carries in a given language, used for both
/// a CVE's summary and a weakness's text. The language is kept because the feed
/// ships several and only the English one is read.
#[derive(Deserialize)]
struct Description {
    lang: String,
    value: String,
}

/// The CVSS scores a record carries, newest first in the order they are read.
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Metrics {
    #[serde(default)]
    cvss_metric_v31: Vec<Metric>,
    #[serde(default)]
    cvss_metric_v30: Vec<Metric>,
    #[serde(default)]
    cvss_metric_v2: Vec<Metric>,
}

/// One score.
///
/// `base_severity` twice on purpose, and it is not a mistake in the feed: CVSS
/// 3.x puts the severity inside `cvssData` beside the score it was derived from,
/// and CVSS 2 puts it on the metric because version 2 of the specification had
/// no such field and NVD added one. Reading only the 3.x position drops every
/// record old enough to carry version 2 alone.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Metric {
    #[serde(default)]
    base_severity: Option<String>,
    #[serde(default)]
    cvss_data: CvssData,
}

/// The inner `cvssData` object of a 3.x metric, where that version of the
/// specification puts the severity beside the score it was derived from. See
/// [`Metric`] for why the same field is read from two places.
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssData {
    #[serde(default)]
    base_severity: Option<String>,
}

/// A weakness the record cites, whose CWE identifier is carried in the text of
/// its [`Description`] rather than a field of its own.
#[derive(Deserialize)]
struct Weakness {
    #[serde(default)]
    description: Vec<Description>,
}

/// One affected-configuration entry, a tree of [`Node`]s the feed uses to express
/// which products and versions the record applies to.
#[derive(Deserialize)]
struct Configuration {
    #[serde(default)]
    nodes: Vec<Node>,
}

/// One node of a [`Configuration`] tree, holding the CPE matches that name the
/// affected products.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Node {
    #[serde(default)]
    cpe_match: Vec<CpeMatch>,
}

/// One CPE the record says is affected, with the range it is affected over.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CpeMatch {
    #[serde(default = "yes")]
    vulnerable: bool,
    #[serde(default)]
    criteria: String,
    version_start_including: Option<String>,
    version_start_excluding: Option<String>,
    version_end_including: Option<String>,
    version_end_excluding: Option<String>,
}

/// The serde default for [`CpeMatch::vulnerable`], which the feed omits when the
/// match is vulnerable and states only to say it is not.
fn yes() -> bool {
    true
}

/// The catalogue document, as [`Catalogue::read`] expects it.
#[derive(Serialize)]
struct Document {
    id: String,
    version: String,
    vulnerability: Vec<Entry>,
}

/// One catalogue entry.
#[derive(Serialize)]
struct Entry {
    cve: String,
    title: String,
    severity: String,
    vendor: String,
    product: String,
    affected: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cwe: Option<u32>,
}

/// Converts one record into however many entries it yields, appending them.
///
/// Zero for most records, which is the ordinary outcome: a record naming no
/// product this corpus can version, carrying no severity, or withdrawn.
fn entries_from(record: &Record, products: &BTreeSet<String>, out: &mut Vec<Entry>) {
    // The 2.0 API's wrapper, unwrapped. A record is either the thing or a box
    // holding it, and everything below reads the thing.
    let record = record.cve.as_deref().unwrap_or(record);

    // A rejected record describes a CVE that was withdrawn. Its ranges are still
    // in the document and mean nothing.
    if record.vuln_status.eq_ignore_ascii_case("rejected") {
        return;
    }
    let (Some(severity), Some(title)) = (severity_of(record), title_of(record)) else {
        return;
    };
    let cwe = cwe_of(record);

    // Deduplicated because NVD repeats a range across configurations more often
    // than not, and a catalogue holding the same claim twice reports it twice.
    let mut seen = BTreeSet::new();
    for configuration in &record.configurations {
        for node in &configuration.nodes {
            for matched in &node.cpe_match {
                let Some((vendor, product, affected)) = affected_range(matched, products) else {
                    continue;
                };
                if !seen.insert((vendor.clone(), product.clone(), affected.clone())) {
                    continue;
                }
                out.push(Entry {
                    cve: record.id.clone(),
                    title: title.clone(),
                    severity: severity.clone(),
                    vendor,
                    product,
                    affected,
                    cwe,
                });
            }
        }
    }
}

/// The `vendor`, `product` and `affected` clause one CPE match yields, where it
/// names something this corpus can version.
///
/// [`None`] for a CPE naming something else, one marked not vulnerable — those
/// appear in a configuration to say what a vulnerability needs *present*, not
/// what it affects — and one stating neither a range nor a version, which is a
/// claim about a product rather than about a release.
fn affected_range(
    matched: &CpeMatch,
    products: &BTreeSet<String>,
) -> Option<(String, String, String)> {
    if !matched.vulnerable {
        return None;
    }

    // `cpe:2.3:a:vendor:product:version:...`, and only `a:`. See the module
    // documentation for why an operating system's is not usable here.
    let mut parts = matched.criteria.split(':');
    if parts.next()? != "cpe" || parts.next()? != "2.3" || parts.next()? != "a" {
        return None;
    }
    let vendor = parts.next()?;
    let product = parts.next()?;
    let version = parts.next()?;

    let key = format!("{vendor}:{product}");
    if !products.contains(&key) {
        return None;
    }

    let clauses: Vec<String> = [
        (">=", &matched.version_start_including),
        (">", &matched.version_start_excluding),
        ("<=", &matched.version_end_including),
        ("<", &matched.version_end_excluding),
    ]
    .iter()
    .filter_map(|(op, bound)| bound.as_ref().map(|value| format!("{op} {value}")))
    .collect();

    let affected = match clauses.is_empty() {
        // No range, so the CPE's own version field is the claim — unless it is
        // the wildcard, which says every release and is what a product-level
        // KEV entry already says better.
        true if matches!(version, "*" | "-" | "") => return None,
        true => format!("== {version}"),
        false => clauses.join(", "),
    };
    Some((vendor.to_string(), product.to_string(), affected))
}

/// The severity a record carries, preferring the newest scoring it has.
///
/// CVSS 3.1 over 3.0 over 2, because a record scored under several carries the
/// same judgement expressed with increasing precision, and the newest is the one
/// NVD would show. [`None`] where a record is scored under none, which is every
/// record still awaiting analysis.
fn severity_of(record: &Record) -> Option<String> {
    [
        &record.metrics.cvss_metric_v31,
        &record.metrics.cvss_metric_v30,
        &record.metrics.cvss_metric_v2,
    ]
    .into_iter()
    .flatten()
    .find_map(|metric| {
        metric
            .cvss_data
            .base_severity
            .as_deref()
            .or(metric.base_severity.as_deref())
    })
    .map(str::to_ascii_lowercase)
}

/// The first sentence of the English description, as the entry's title.
///
/// A description is a paragraph and a title is a label. The first sentence is
/// almost always the statement of what the vulnerability is, with the rest
/// giving the conditions, so this reads as a title far more often than a
/// truncation has any right to.
fn title_of(record: &Record) -> Option<String> {
    let english = record
        .descriptions
        .iter()
        .find(|description| description.lang == "en")?;

    let mut title = String::with_capacity(MAX_TITLE_BYTES);
    let mut whitespace = false;
    for character in english.value.trim().chars() {
        if character.is_whitespace() {
            whitespace = !title.is_empty();
            continue;
        }
        if whitespace {
            // A sentence ends at a full stop followed by a space, which is what
            // separates it from the dots inside `4.9.1` and `e.g.`.
            if title.ends_with('.') || title.ends_with('!') || title.ends_with('?') {
                break;
            }
            title.push(' ');
            whitespace = false;
        }
        if title.len() + character.len_utf8() > MAX_TITLE_BYTES {
            break;
        }
        title.push(character);
    }

    let title = title.trim_end_matches(['.', ' ']).to_string();
    (!title.is_empty()).then_some(title)
}

/// The CWE a record names, where it names one as a number.
///
/// NVD writes several kinds of non-answer in this field — `NVD-CWE-noinfo`,
/// `NVD-CWE-Other`, `Unsure` — and each is a statement that nobody classified
/// it. The first real number wins, and no number at all is [`None`] rather than
/// a placeholder.
fn cwe_of(record: &Record) -> Option<u32> {
    record
        .weaknesses
        .iter()
        .flat_map(|weakness| weakness.description.iter())
        .filter(|description| description.lang == "en")
        .find_map(|description| description.value.strip_prefix("CWE-")?.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn products(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| (*name).to_string()).collect()
    }

    /// One record in the shape the reconstructed feed publishes, carrying the
    /// exim range that this crate's shipped seed states by hand.
    const EXIM: &str = r#"{
      "timestamp": "2026-09-08T00:00:09+00:00",
      "cve_count": 1,
      "cve_items": [{
        "id": "CVE-2019-10149",
        "vulnStatus": "Analyzed",
        "descriptions": [
          {"lang": "es", "value": "Se descubrio un fallo."},
          {"lang": "en", "value": "A flaw was found in Exim 4.87 to 4.91. Improper validation of recipient address."}
        ],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}]},
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-78"}]}],
        "configurations": [{"nodes": [{"cpeMatch": [
          {"vulnerable": true, "criteria": "cpe:2.3:a:exim:exim:*:*:*:*:*:*:*:*",
           "versionStartIncluding": "4.87", "versionEndIncluding": "4.91"},
          {"vulnerable": true, "criteria": "cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*"}
        ]}]}]
      }]
    }"#;

    /// The conversion reproduces, from the feed, the entry somebody wrote by
    /// hand into `assets/cve/seed.toml`.
    ///
    /// The strongest thing this file can assert. The seed's exim entry says
    /// `>= 4.87, <= 4.91` and was written by reading the advisory; if the
    /// generated one says the same thing, the range translation is right for
    /// every other record too.
    #[test]
    fn a_record_converts_to_the_entry_a_person_wrote_by_hand() {
        let document = to_document_for(&mut EXIM.as_bytes(), &products(&["exim:exim"]))
            .expect("the feed converts");

        assert!(document.contains(r#"cve = "CVE-2019-10149""#), "{document}");
        assert!(
            document.contains(r#"affected = ">= 4.87, <= 4.91""#),
            "{document}"
        );
        assert!(document.contains(r#"severity = "critical""#), "{document}");
        assert!(document.contains(r#"vendor = "exim""#), "{document}");
        assert!(document.contains(r#"product = "exim""#), "{document}");
        assert!(document.contains("cwe = 78"), "{document}");

        // The title is the first sentence, and the Spanish description beside it
        // is not consulted.
        assert!(
            document.contains(r#"title = "A flaw was found in Exim 4.87 to 4.91""#),
            "{document}"
        );
    }

    /// The operating system named in the same record is not converted. A Debian
    /// 9 CPE says which distribution shipped the flawed exim, not that every
    /// Debian 9 host has it.
    #[test]
    fn an_operating_system_cpe_is_left_alone() {
        let document = to_document_for(
            &mut EXIM.as_bytes(),
            &products(&["exim:exim", "debian:debian_linux"]),
        )
        .expect("the feed converts");

        assert!(!document.contains("debian"), "{document}");
        assert_eq!(document.matches("[[vulnerability]]").count(), 1);
    }

    /// A product the corpus cannot name with a version is dropped, however
    /// well-formed its record. This is the filter the whole module turns on.
    #[test]
    fn a_product_the_corpus_cannot_version_is_dropped() {
        let document = to_document_for(&mut EXIM.as_bytes(), &products(&["nothing:at_all"]))
            .expect("converts");

        assert_eq!(
            document.matches("[[vulnerability]]").count(),
            0,
            "{document}"
        );
        // Still a catalogue, and still named and dated: an empty result is a
        // legitimate answer, not a failure.
        assert!(document.contains(r#"id = "nvd:cve""#), "{document}");
        assert!(document.contains(r#"version = "2026.9.8""#), "{document}");
    }

    /// Disjoint ranges become one entry each, because `affected` is a
    /// conjunction and cannot say "or".
    #[test]
    fn disjoint_ranges_become_separate_entries() {
        const REGRESSHION: &str = r#"{
          "timestamp": "2026-09-08T00:00:00+00:00",
          "cve_items": [{
            "id": "CVE-2024-6387",
            "descriptions": [{"lang": "en", "value": "A signal handler race condition in OpenSSH."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]},
            "configurations": [{"nodes": [{"cpeMatch": [
              {"vulnerable": true, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
               "versionEndExcluding": "4.4"},
              {"vulnerable": true, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
               "versionStartIncluding": "8.5", "versionEndExcluding": "9.8"}
            ]}]}]
          }]
        }"#;

        let document =
            to_document_for(&mut REGRESSHION.as_bytes(), &products(&["openbsd:openssh"]))
                .expect("converts");

        assert_eq!(
            document.matches("[[vulnerability]]").count(),
            2,
            "{document}"
        );
        assert!(document.contains(r#"affected = "< 4.4""#), "{document}");
        assert!(
            document.contains(r#"affected = ">= 8.5, < 9.8""#),
            "{document}"
        );
    }

    /// The same range stated twice in two configurations is one entry. NVD
    /// repeats itself constantly and a catalogue that did would report a finding
    /// twice.
    #[test]
    fn a_repeated_range_is_recorded_once() {
        const REPEATED: &str = r#"{
          "timestamp": "2026-01-02T00:00:00+00:00",
          "cve_items": [{
            "id": "CVE-2024-0001",
            "descriptions": [{"lang": "en", "value": "Something in Tomcat."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "MEDIUM"}}]},
            "configurations": [
              {"nodes": [{"cpeMatch": [{"vulnerable": true,
                "criteria": "cpe:2.3:a:apache:tomcat:9.0.1:*:*:*:*:*:*:*"}]}]},
              {"nodes": [{"cpeMatch": [{"vulnerable": true,
                "criteria": "cpe:2.3:a:apache:tomcat:9.0.1:*:*:*:*:*:*:*"}]}]}
            ]
          }]
        }"#;

        let document = to_document_for(&mut REPEATED.as_bytes(), &products(&["apache:tomcat"]))
            .expect("converts");

        assert_eq!(
            document.matches("[[vulnerability]]").count(),
            1,
            "{document}"
        );
        assert!(document.contains(r#"affected = "== 9.0.1""#), "{document}");
    }

    /// A CVSS 2 record is scored. Its severity sits on the metric rather than
    /// inside `cvssData`, and reading only the newer position would silently
    /// drop every record old enough to predate CVSS 3.
    #[test]
    fn a_cvss_2_record_is_still_scored() {
        const OLD: &str = r#"{
          "timestamp": "2026-01-02T00:00:00+00:00",
          "cve_items": [{
            "id": "CVE-2009-0001",
            "descriptions": [{"lang": "en", "value": "An old flaw in ProFTPD."}],
            "metrics": {"cvssMetricV2": [{"baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}]},
            "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": true,
              "criteria": "cpe:2.3:a:proftpd:proftpd:1.3.1:*:*:*:*:*:*:*"}]}]}]
          }]
        }"#;

        let document = to_document_for(&mut OLD.as_bytes(), &products(&["proftpd:proftpd"]))
            .expect("converts");
        assert!(document.contains(r#"severity = "high""#), "{document}");
    }

    /// Records nothing can be concluded from are skipped rather than converted
    /// into an entry that says nothing: a withdrawn CVE, one nobody has scored,
    /// a CPE marked as a precondition rather than a target, and a wildcard
    /// version, which is a claim about a product and not about a release.
    #[test]
    fn a_record_with_nothing_to_say_yields_nothing() {
        const NOTHING: &str = r#"{
          "timestamp": "2026-01-02T00:00:00+00:00",
          "cve_items": [
            {"id": "CVE-2024-1", "vulnStatus": "Rejected",
             "descriptions": [{"lang": "en", "value": "Withdrawn."}],
             "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]},
             "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": true,
               "criteria": "cpe:2.3:a:apache:tomcat:9.0.1:*:*:*:*:*:*:*"}]}]}]},
            {"id": "CVE-2024-2",
             "descriptions": [{"lang": "en", "value": "Not yet scored."}],
             "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": true,
               "criteria": "cpe:2.3:a:apache:tomcat:9.0.2:*:*:*:*:*:*:*"}]}]}]},
            {"id": "CVE-2024-3",
             "descriptions": [{"lang": "en", "value": "Needs something present."}],
             "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]},
             "configurations": [{"nodes": [{"cpeMatch": [
               {"vulnerable": false, "criteria": "cpe:2.3:a:apache:tomcat:9.0.3:*:*:*:*:*:*:*"},
               {"vulnerable": true, "criteria": "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"}
             ]}]}]}
          ]
        }"#;

        let document = to_document_for(&mut NOTHING.as_bytes(), &products(&["apache:tomcat"]))
            .expect("converts");
        assert_eq!(
            document.matches("[[vulnerability]]").count(),
            0,
            "{document}"
        );
    }

    /// The 2.0 API nests the record under `cve` and the reconstructed feed does
    /// not. Both are read, so a caller assembling API pages needs no conversion
    /// of their own.
    #[test]
    fn the_api_shape_is_read_as_well_as_the_feed_shape() {
        const NESTED: &str = r#"{
          "timestamp": "2026-01-02T00:00:00+00:00",
          "vulnerabilities": [{"cve": {
            "id": "CVE-2024-0002",
            "descriptions": [{"lang": "en", "value": "Something in Tomcat."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "LOW"}}]},
            "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": true,
              "criteria": "cpe:2.3:a:apache:tomcat:10.1.0:*:*:*:*:*:*:*"}]}]}]
          }}]
        }"#;

        let document = to_document_for(&mut NESTED.as_bytes(), &products(&["apache:tomcat"]))
            .expect("converts");
        assert!(document.contains(r#"cve = "CVE-2024-0002""#), "{document}");
        assert!(document.contains(r#"affected = "== 10.1.0""#), "{document}");
    }

    /// The whole point, end to end: a feed converts, reads back as a catalogue,
    /// and its range decides a host.
    ///
    /// Two hosts differing only in their exim version, one inside the range and
    /// one past it. A catalogue that fired on both would be no better than the
    /// product-level claim KEV already makes, and the version range is the
    /// entire reason to prefer this feed over that one.
    ///
    /// `read` consults the shipped corpus rather than a stated filter, so this
    /// also checks that the real one admits exim.
    #[test]
    fn a_converted_range_tells_two_versions_apart() {
        use crate::model::host::Host;
        use crate::model::port::{Port, PortState, Protocol, Service};

        let catalogue = read(&mut EXIM.as_bytes()).expect("the feed reads as a catalogue");
        assert_eq!(catalogue.id(), NVD_ID);
        assert_eq!(catalogue.len(), 1);

        let matched = |version: &str| {
            let mut host = Host::new("192.0.2.1".parse().expect("an address"));
            let service = Service::new("smtp", 90).with_cpe(format!("cpe:/a:exim:exim:{version}"));
            host.add_port(Port::new(25, Protocol::Tcp, PortState::Open).with_service(service));
            crate::cve::correlate_with(&mut host, &catalogue);
            host.ports()
                .find(|port| port.number() == 25)
                .expect("the port")
                .findings()
                .any(|finding| finding.detection().id() == NVD_ID)
        };

        assert!(matched("4.90"), "4.90 is inside >= 4.87, <= 4.91");
        assert!(
            !matched("4.92"),
            "4.92 is past the range and must not match"
        );
    }

    /// A feed that does not date itself still converts. `0.0.0` sorts below
    /// every real version and says plainly that the date is unknown, which beats
    /// inventing today's.
    #[test]
    fn an_undated_feed_takes_a_version_that_says_so() {
        assert_eq!(feed_version("2026-09-08T00:00:09+00:00"), "2026.9.8");
        assert_eq!(feed_version("2024-01-02"), "2024.1.2");
        assert_eq!(feed_version(""), "0.0.0");
        assert_eq!(feed_version("last Tuesday"), "0.0.0");
    }

    /// A description that is one long sentence is cut, and cut without splitting
    /// a character. The version numbers inside it do not end the sentence.
    #[test]
    fn a_title_is_a_sentence_and_never_longer_than_the_cap() {
        let record = Record {
            cve: None,
            id: String::new(),
            vuln_status: String::new(),
            descriptions: vec![Description {
                lang: "en".into(),
                value: format!("A flaw in version 1.2.3 of the thing {}", "x".repeat(400)),
            }],
            metrics: Metrics::default(),
            weaknesses: Vec::new(),
            configurations: Vec::new(),
        };

        let title = title_of(&record).expect("a title");
        assert!(title.len() <= MAX_TITLE_BYTES, "{}", title.len());
        assert!(
            title.starts_with("A flaw in version 1.2.3 of the thing"),
            "the dots in a version number do not end the sentence: {title}"
        );
    }
}
