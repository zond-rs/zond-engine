// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # CISA's Known Exploited Vulnerabilities catalogue
//!
//! Turns the JSON CISA publishes into a [`Catalogue`] the correlator can use.
//! The answer to the first question anybody asks after seeing that
//! [`cve`](crate::cve) takes its dataset as a parameter: how do I point it at the
//! real one.
//!
//! ```no_run
//! use std::fs::File;
//! use std::io::BufReader;
//!
//! let file = File::open("known_exploited_vulnerabilities.json")?;
//! let catalogue = zond_engine::import::kev::read(&mut BufReader::new(file))?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## It converts to a document rather than straight to a catalogue
//!
//! [`to_document`] emits the TOML that [`Catalogue::read`] already consumes, and
//! [`read`] is the two of those in sequence. The extra step buys two things. A
//! caller can write the document out and keep it, which turns a feed fetched over
//! the network into a file a scan can be re-run against and a report traced back
//! to. And there is only one parser: a converted catalogue is checked by exactly
//! the code that checks a hand-written one, so nothing can arrive through this
//! path that could not have been written by hand.
//!
//! ## What KEV does not carry, and what that costs
//!
//! **No versions.** A KEV entry names a vendor and a product and stops there:
//! `Apache` / `HTTP Server`, with no indication of which releases are affected.
//! The catalogue grammar has a word for that, `affected = "*"`, and
//! [`cve`](crate::cve) reads it honestly: an entry naming no version matches a
//! patched installation as readily as a vulnerable one, so its findings are
//! [`Confidence::Weak`](crate::model::confidence::Confidence::Weak) and say in
//! the excerpt that no version was checked. What a converted KEV tells an
//! operator is "this host runs software with vulnerabilities known to be
//! exploited in the wild, go and check the version", which is worth saying and
//! is not the same claim as a version match.
//!
//! **No severities.** Every entry is in the catalogue because it is being
//! exploited, so the severity comes from the one distinction KEV does draw:
//! `knownRansomwareCampaignUse`. Entries used in ransomware campaigns are
//! [`Critical`](crate::model::finding::Severity::Critical) and the rest are
//! [`High`](crate::model::finding::Severity::High). Nothing here is lower than
//! that; inclusion in KEV is itself the finding.
//!
//! **Names, not identifiers.** KEV writes what a person would read, and the
//! correlator matches the identifiers a CPE carries. [`cpe_identity`] normalises
//! between them, and it is a heuristic: `HTTP Server` becomes `http_server` and
//! matches, `Adaptive Security Appliance (ASA)` becomes
//! `adaptive_security_appliance_asa` and does not. The failures are all in the
//! safe direction, since a name that does not normalise to the CPE identity
//! simply never matches, but they are failures and there is no dictionary here
//! to fix them.
//!
//! So a converted catalogue holds every KEV entry and correlates against a small
//! part of it: the network-reachable software this engine's fingerprint corpus
//! names. Most of KEV is browsers, phones and appliance firmware that no port
//! scan identifies, which is a property of the two datasets rather than of the
//! conversion.

use std::io::BufRead;

use serde::{Deserialize, Serialize};

use crate::cve::{Catalogue, CatalogueError, MAX_DOCUMENT_BYTES};

/// What a converted catalogue names itself.
///
/// CISA's, not this engine's. The `zond:` namespace is what this crate ships and
/// is refused to anything read from outside; a converted KEV is somebody else's
/// data passing through, and a report saying so is a report a reader can trace.
pub const KEV_ID: &str = "cisa:kev";

/// Why a KEV catalogue could not be converted.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum KevError {
    /// The bytes could not be read.
    #[error("the KEV catalogue could not be read: {0}")]
    Io(#[from] std::io::Error),

    /// The document is not the JSON CISA publishes.
    #[error("the KEV catalogue is malformed: {0}")]
    Malformed(String),

    /// The document was longer than [`MAX_DOCUMENT_BYTES`].
    #[error("the KEV catalogue is longer than the {limit} byte limit")]
    TooLarge {
        /// The limit it passed.
        limit: u64,
    },

    /// The converted document was refused by the catalogue reader, which is a
    /// defect in the conversion rather than in the feed.
    #[error("the converted catalogue was refused: {0}")]
    Rejected(#[from] CatalogueError),
}

/// Converts the KEV JSON in `input` into the TOML document
/// [`Catalogue::read`] consumes.
///
/// The result names itself [`KEV_ID`] and carries CISA's own `catalogVersion`,
/// so two scans run against two dumps of the feed are visibly different in the
/// report.
///
/// # Errors
///
/// [`KevError::Malformed`] for JSON that is not this feed, and
/// [`KevError::TooLarge`] past [`MAX_DOCUMENT_BYTES`].
pub fn to_document(input: &mut dyn BufRead) -> Result<String, KevError> {
    // Bounded before the read, on the reasoning `Catalogue::read` gives: this is
    // by definition a feed fetched from somewhere else, and a source with no end
    // must not be held in memory to discover it had none.
    let mut source = String::new();
    let read = {
        use std::io::Read as _;
        std::io::Read::take(input, MAX_DOCUMENT_BYTES.saturating_add(1))
            .read_to_string(&mut source)?
    };
    if read as u64 > MAX_DOCUMENT_BYTES {
        return Err(KevError::TooLarge {
            limit: MAX_DOCUMENT_BYTES,
        });
    }

    let feed: Feed =
        serde_json::from_str(&source).map_err(|error| KevError::Malformed(error.to_string()))?;

    let document = Document {
        id: KEV_ID.to_string(),
        version: catalogue_version(&feed.catalog_version),
        vulnerability: feed.vulnerabilities.iter().map(Entry::from).collect(),
    };

    // Serialised rather than written by hand. Every string here is CISA's, and a
    // product name carrying a quote or a backslash would end a hand-written
    // document early or change what came after it.
    toml::to_string(&document).map_err(|error| KevError::Malformed(error.to_string()))
}

/// Reads the KEV JSON in `input` as a [`Catalogue`].
///
/// [`to_document`] and [`Catalogue::read`] in sequence, which is the ordinary
/// call. Convert once with [`to_document`] and keep the result where a scan is
/// re-run against the same feed.
///
/// # Errors
///
/// Everything [`to_document`] returns, and [`KevError::Rejected`] where the
/// document it produced was refused.
pub fn read(input: &mut dyn BufRead) -> Result<Catalogue, KevError> {
    let document = to_document(input)?;
    Ok(Catalogue::read(&mut document.as_bytes())?)
}

/// The identity a CPE would carry for a name KEV writes for a person.
///
/// Lower-cased, with runs of anything that is not alphanumeric, a hyphen, a dot
/// or an underscore collapsed to a single underscore. `HTTP Server` becomes
/// `http_server` and `D-Link` stays `d-link`, which are the identities CPE uses
/// for both.
///
/// A heuristic, and the one place this conversion can be wrong. There is no CPE
/// dictionary here to check a name against, so a product whose registered
/// identity is not its display name with the spaces replaced does not match:
/// `Adaptive Security Appliance (ASA)` normalises to
/// `adaptive_security_appliance_asa` where CPE says
/// `adaptive_security_appliance`. Every such failure is a finding not raised
/// rather than one raised wrongly, which is the direction to be wrong in.
pub fn cpe_identity(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut pending_separator = false;

    for character in name.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '_') {
            if pending_separator && !out.is_empty() {
                out.push('_');
            }
            pending_separator = false;
            out.push(character.to_ascii_lowercase());
        } else {
            pending_separator = true;
        }
    }
    out
}

/// CISA's `catalogVersion` as the catalogue grammar's `major.minor.patch`.
///
/// The feed writes a date, `2026.09.03`, whose components are already the three
/// a version wants once the leading zeros are gone. Anything else is carried
/// through untouched and refused by [`Catalogue::read`], which is the reader that
/// owns that grammar.
fn catalogue_version(declared: &str) -> String {
    let parts: Vec<&str> = declared.split('.').collect();
    if parts.len() != 3
        || !parts
            .iter()
            .all(|part| part.chars().all(|c| c.is_ascii_digit()))
    {
        return declared.to_string();
    }
    parts
        .iter()
        .map(|part| part.trim_start_matches('0'))
        .map(|part| if part.is_empty() { "0" } else { part })
        .collect::<Vec<_>>()
        .join(".")
}

// ---------------------------------------------------------------------------
// The feed, and the document it becomes
// ---------------------------------------------------------------------------

/// The KEV feed, of which only what the correlator can use is read.
#[derive(Debug, Deserialize)]
struct Feed {
    #[serde(default, rename = "catalogVersion")]
    catalog_version: String,
    #[serde(default)]
    vulnerabilities: Vec<KevEntry>,
}

/// One KEV entry.
#[derive(Debug, Deserialize)]
struct KevEntry {
    #[serde(default, rename = "cveID")]
    cve_id: String,
    #[serde(default, rename = "vendorProject")]
    vendor_project: String,
    #[serde(default)]
    product: String,
    #[serde(default, rename = "vulnerabilityName")]
    vulnerability_name: String,
    #[serde(default, rename = "requiredAction")]
    required_action: String,
    #[serde(default, rename = "knownRansomwareCampaignUse")]
    known_ransomware_campaign_use: String,
    #[serde(default)]
    cwes: Vec<String>,
}

/// The catalogue document a conversion produces.
#[derive(Debug, Serialize)]
struct Document {
    id: String,
    version: String,
    vulnerability: Vec<Entry>,
}

/// One entry of it, in the shape [`Catalogue::read`] expects.
#[derive(Debug, Serialize)]
struct Entry {
    cve: String,
    title: String,
    severity: String,
    vendor: String,
    product: String,
    affected: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cwe: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation: Option<String>,
}

impl From<&KevEntry> for Entry {
    fn from(entry: &KevEntry) -> Self {
        Self {
            cve: entry.cve_id.clone(),
            // The catalogue refuses an entry with no title, and a KEV row
            // without one is still worth carrying: it has a CVE, and that names
            // the vulnerability well enough for a reader to look it up.
            title: match entry.vulnerability_name.trim().is_empty() {
                true => format!("{} known exploited vulnerability", entry.cve_id),
                false => entry.vulnerability_name.clone(),
            },
            // Inclusion in KEV is the finding. The one distinction the feed
            // draws between its entries is whether ransomware operators are
            // using them, and that is the one this carries.
            severity: match entry
                .known_ransomware_campaign_use
                .eq_ignore_ascii_case("known")
            {
                true => "critical",
                false => "high",
            }
            .to_string(),
            vendor: cpe_identity(&entry.vendor_project),
            product: cpe_identity(&entry.product),
            // The feed carries no version data at all; see the module
            // documentation for what that costs and how it is reported.
            affected: "*".to_string(),
            cwe: entry.cwes.first().and_then(|cwe| {
                cwe.trim()
                    .strip_prefix("CWE-")
                    .and_then(|number| number.parse().ok())
            }),
            remediation: match entry.required_action.trim().is_empty() {
                true => None,
                false => Some(entry.required_action.clone()),
            },
        }
    }
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

    /// Two rows of the real feed, field for field as CISA publishes them.
    const FEED: &str = r#"{
      "title": "CISA Catalog of Known Exploited Vulnerabilities",
      "catalogVersion": "2026.09.03",
      "count": 2,
      "vulnerabilities": [
        {
          "cveID": "CVE-2021-41773",
          "vendorProject": "Apache",
          "product": "HTTP Server",
          "vulnerabilityName": "Apache HTTP Server Path Traversal Vulnerability",
          "dateAdded": "2021-11-03",
          "shortDescription": "Apache HTTP Server contains a path traversal vulnerability.",
          "requiredAction": "Apply updates per vendor instructions.",
          "dueDate": "2021-11-17",
          "knownRansomwareCampaignUse": "Unknown",
          "notes": "",
          "cwes": ["CWE-22"]
        },
        {
          "cveID": "CVE-2023-4966",
          "vendorProject": "Citrix",
          "product": "NetScaler ADC and NetScaler Gateway",
          "vulnerabilityName": "Citrix NetScaler Buffer Overflow Vulnerability",
          "dateAdded": "2023-10-18",
          "shortDescription": "Sensitive information disclosure.",
          "requiredAction": "Apply mitigations per vendor instructions.",
          "dueDate": "2023-11-08",
          "knownRansomwareCampaignUse": "Known",
          "notes": "",
          "cwes": ["CWE-119"]
        }
      ]
    }"#;

    fn converted() -> Catalogue {
        read(&mut FEED.as_bytes()).expect("the feed converts")
    }

    /// A KEV name is what a person reads and a CPE identity is what the
    /// correlator matches, and the whole conversion turns on the two agreeing.
    #[test]
    fn a_display_name_becomes_the_identity_a_cpe_carries() {
        assert_eq!(cpe_identity("Apache"), "apache");
        assert_eq!(cpe_identity("HTTP Server"), "http_server");
        assert_eq!(cpe_identity("OpenBSD"), "openbsd");
        // A hyphen is part of the identity rather than punctuation to strip:
        // CPE writes this vendor with one.
        assert_eq!(cpe_identity("D-Link"), "d-link");
        assert_eq!(cpe_identity("Windows Server 2019"), "windows_server_2019");
        // Runs of punctuation collapse rather than each leaving a separator.
        assert_eq!(cpe_identity("Foo   Bar"), "foo_bar");
        assert_eq!(cpe_identity("  Leading"), "leading");
        assert_eq!(cpe_identity(""), "");
    }

    /// The heuristic's own limit, written down as a test rather than left for
    /// somebody to discover: a display name that is not the identity with its
    /// spaces replaced does not match, and this is what that looks like.
    #[test]
    fn a_name_cpe_spells_differently_does_not_normalise_to_it() {
        assert_eq!(
            cpe_identity("Adaptive Security Appliance (ASA)"),
            "adaptive_security_appliance_asa",
            "CPE says 'adaptive_security_appliance', so this entry will not match"
        );
    }

    /// The feed's date is already the three components a version wants.
    #[test]
    fn the_feeds_own_version_becomes_the_catalogues() {
        assert_eq!(catalogue_version("2026.09.03"), "2026.9.3");
        assert_eq!(catalogue_version("2026.10.30"), "2026.10.30");
        assert_eq!(catalogue_version("2026.01.01"), "2026.1.1");
        // Anything else is carried through for the catalogue reader to refuse,
        // rather than guessed at here.
        assert_eq!(catalogue_version("not-a-date"), "not-a-date");
    }

    /// The conversion produces a document the catalogue reader accepts, which is
    /// the property the two-step shape exists to guarantee.
    #[test]
    fn a_converted_feed_is_a_document_the_catalogue_reader_accepts() {
        let catalogue = converted();
        assert_eq!(catalogue.id(), KEV_ID);
        assert_eq!(catalogue.version().to_string(), "2026.9.3");
        assert_eq!(catalogue.len(), 2);
    }

    /// Every field the correlator reads survives the crossing.
    #[test]
    fn an_entry_carries_what_the_correlator_matches_on() {
        let document = to_document(&mut FEED.as_bytes()).expect("converts");

        assert!(document.contains(r#"cve = "CVE-2021-41773""#));
        assert!(document.contains(r#"vendor = "apache""#));
        assert!(document.contains(r#"product = "http_server""#));
        assert!(document.contains(r#"affected = "*""#));
        assert!(document.contains("cwe = 22"));
        assert!(document.contains("Apply updates per vendor instructions."));
    }

    /// KEV grades nothing, so the severity comes from the one distinction it
    /// does draw. An entry ransomware operators are using outranks one they are
    /// not, and nothing is below high: being in this catalogue at all means the
    /// vulnerability is being exploited.
    #[test]
    fn ransomware_use_is_the_one_distinction_the_feed_offers() {
        let document = to_document(&mut FEED.as_bytes()).expect("converts");
        assert!(
            document.contains(r#"severity = "critical""#),
            "the Citrix row"
        );
        assert!(document.contains(r#"severity = "high""#), "the Apache row");
    }

    /// The correlation a converted feed actually produces, end to end, and the
    /// honesty that has to come with it.
    ///
    /// KEV names no version, so the entry matches a patched server exactly as it
    /// matches a vulnerable one. The finding is still worth raising, and it has
    /// to say what it is: `Weak`, with an excerpt that does not claim a version
    /// was checked. Reporting this at the confidence of a version match would put
    /// a fully patched host and a vulnerable one in the same row.
    #[test]
    fn a_kev_finding_says_that_no_version_was_checked() {
        use crate::model::confidence::Confidence;
        use crate::model::host::Host;
        use crate::model::port::{Port, PortState, Protocol, Service};

        let catalogue = converted();
        let mut host = Host::new("192.0.2.1".parse().expect("an address"));
        // A current, patched Apache. KEV cannot tell it from a vulnerable one.
        let service = Service::new("http", 90).with_cpe("cpe:/a:apache:http_server:2.4.62");
        host.add_port(Port::new(80, Protocol::Tcp, PortState::Open).with_service(service));

        crate::cve::correlate_with(&mut host, &catalogue);

        let port = host
            .ports()
            .find(|port| port.number() == 80)
            .expect("the port");
        let finding = port
            .findings()
            .find(|finding| finding.detection().id() == KEV_ID)
            .expect("the entry matched on the product");

        assert_eq!(
            finding.confidence(),
            Confidence::Weak,
            "an entry that checked no version must not read as one that did"
        );
        assert!(
            finding.excerpt().as_str().contains("not checked"),
            "the excerpt has to say the version was never in question"
        );
    }

    /// A feed longer than the ceiling is refused rather than buffered, on the
    /// reasoning the catalogue reader gives: this comes off a socket.
    #[test]
    fn a_feed_past_the_ceiling_is_refused() {
        let huge = format!(
            r#"{{"catalogVersion":"2026.1.1","vulnerabilities":[],"pad":"{}"}}"#,
            "x".repeat(MAX_DOCUMENT_BYTES as usize + 16)
        );
        assert!(matches!(
            to_document(&mut huge.as_bytes()),
            Err(KevError::TooLarge { .. })
        ));
    }

    /// Anything that is not the feed is refused by name rather than producing an
    /// empty catalogue, which would read as a scan that found nothing wrong.
    #[test]
    fn what_is_not_the_feed_is_refused() {
        for text in ["", "not json", "{}", r#"{"vulnerabilities": 3}"#] {
            let outcome = read(&mut text.as_bytes());
            assert!(
                outcome.is_err(),
                "'{text}' produced a catalogue rather than an error"
            );
        }
    }

    /// Every string here is CISA's text and none of it is this crate's, so a
    /// name carrying TOML syntax must not become TOML structure.
    ///
    /// Two different defences, and the test covers both because they protect
    /// different fields. A vendor or product is normalised by [`cpe_identity`],
    /// which keeps alphanumerics and three punctuation marks and drops the rest,
    /// so quotes and newlines never reach the document at all. A title and a
    /// remediation are carried through verbatim and are safe only because the
    /// document is serialised rather than written by hand.
    #[test]
    fn a_name_carrying_toml_syntax_does_not_become_toml_structure() {
        let hostile = r#"{
          "catalogVersion": "2026.1.1",
          "vulnerabilities": [{
            "cveID": "CVE-2026-0001",
            "vendorProject": "Acme",
            "product": "Widget\", affected = \"*\"\nmalicious = \"yes",
            "vulnerabilityName": "Title\"\nseverity = \"info\"\ninjected = \"yes",
            "requiredAction": "",
            "knownRansomwareCampaignUse": "Unknown",
            "cwes": []
          }]
        }"#;

        let document = to_document(&mut hostile.as_bytes()).expect("converts");

        // Parsed rather than scanned for text. Both hostile strings survive
        // inside the document as *values*, and a line-based check cannot tell a
        // key from the contents of a multi-line string, which is exactly what
        // the serialiser produced here. What matters is the shape the parser
        // sees.
        let parsed: toml::Value = toml::from_str(&document).expect("the document parses");
        let table = parsed.as_table().expect("a table");
        assert_eq!(
            table.keys().collect::<Vec<_>>(),
            vec!["id", "version", "vulnerability"],
            "a name opened a key of its own"
        );

        let entries = table["vulnerability"].as_array().expect("an array");
        assert_eq!(entries.len(), 1, "one entry in, one entry out");
        let entry = entries[0].as_table().expect("a table");
        assert!(
            !entry.contains_key("injected") && !entry.contains_key("malicious"),
            "a name opened a key inside the entry"
        );
        assert_eq!(
            entry["severity"].as_str(),
            Some("high"),
            "the title's injected severity did not take"
        );

        // And the severity this crate chose is the one that survived, rather
        // than the one the hostile title tried to set.
        let catalogue = read(&mut hostile.as_bytes()).expect("reads");
        assert_eq!(catalogue.len(), 1, "one entry in, one entry out");

        use crate::model::finding::Severity;
        use crate::model::host::Host;
        use crate::model::port::{Port, PortState, Protocol, Service};

        let mut host = Host::new("192.0.2.1".parse().expect("an address"));
        let service =
            Service::new("http", 90).with_cpe("cpe:/a:acme:widget_affected_malicious_yes:1.0");
        host.add_port(Port::new(80, Protocol::Tcp, PortState::Open).with_service(service));
        crate::cve::correlate_with(&mut host, &catalogue);

        let port = host
            .ports()
            .find(|port| port.number() == 80)
            .expect("the port");
        let finding = port.findings().next().expect("the entry matched");
        assert_eq!(
            finding.severity(),
            Severity::High,
            "the title's injected severity did not take"
        );
    }
}
