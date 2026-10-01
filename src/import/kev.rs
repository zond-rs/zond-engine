// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # CISA's Known Exploited Vulnerabilities catalogue
//!
//! Turns the JSON CISA publishes into one of two things the correlator uses:
//! [`exploited`] reads the list of exploited vulnerabilities, which marks the findings a
//! correlation draws from its other data; [`read`] makes a [`Catalogue`] that draws
//! findings from KEV alone.
//!
//! ```no_run
//! use std::fs::File;
//! use std::io::BufReader;
//! use zond_engine::cve::{Catalogue, Correlator};
//!
//! // Marking what the shipped catalogue finds by today's copy of the list:
//! let file = File::open("known_exploited_vulnerabilities.json")?;
//! let exploited = zond_engine::import::kev::exploited(&mut BufReader::new(file))?;
//! let correlator = Correlator::new(Catalogue::embedded()).with_exploited(&exploited);
//!
//! // Or finding by KEV alone, product by product:
//! let file = File::open("known_exploited_vulnerabilities.json")?;
//! let catalogue = zond_engine::import::kev::read(&mut BufReader::new(file))?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Conversion goes through a document
//!
//! [`to_document`] emits the TOML that [`Catalogue::read`] consumes, and [`read`] is the
//! two in sequence. A caller can keep the document, so a scan can be re-run against the
//! same feed and a report traced back to it. A converted catalogue is checked by the
//! same parser as a hand-written one, so nothing arrives this way that could not have
//! been written by hand.
//!
//! ## What KEV does not carry, and what that costs
//!
//! **No versions.** A KEV entry names a vendor and a product, `Apache` / `HTTP Server`,
//! with no indication of which releases are affected. It converts to `affected = "*"`,
//! which matches a patched installation as readily as a vulnerable one, so its findings
//! are [`Confidence::Weak`](crate::model::confidence::Confidence::Weak) and say in the
//! excerpt that no version was checked. What a converted KEV tells an operator is "this
//! host runs software with vulnerabilities exploited in the wild; check the version".
//!
//! **No severities.** Every entry is being exploited, so the severity comes from the one
//! distinction KEV draws, `knownRansomwareCampaignUse`: entries used in ransomware
//! campaigns are [`Critical`](crate::model::finding::Severity::Critical) and the rest
//! [`High`](crate::model::finding::Severity::High).
//!
//! **Names, not identifiers.** KEV writes display names; the correlator matches CPE
//! identifiers. [`cpe_identity`] normalises between them heuristically: `HTTP Server`
//! becomes `http_server` and matches, `Adaptive Security Appliance (ASA)` becomes
//! `adaptive_security_appliance_asa` and does not. A miss means a finding not raised,
//! never a wrong one, and there is no dictionary here to fix it.
//!
//! So a converted catalogue holds every KEV entry but correlates against only the
//! network-reachable software the fingerprint corpus names. Most of KEV is browsers,
//! phones and appliance firmware that no port scan identifies.

use std::io::BufRead;

use serde::{Deserialize, Serialize};

use crate::cve::{Catalogue, CatalogueError, KnownExploited, MAX_DOCUMENT_BYTES};

/// What a converted catalogue names itself.
///
/// CISA's identity, since the `zond:` namespace is reserved for what this crate ships.
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

    /// The catalogue reader refused the converted document, which is a defect in the
    /// conversion.
    #[error("the converted catalogue was refused: {0}")]
    Rejected(#[from] CatalogueError),
}

/// Converts the KEV JSON in `input` into the TOML document
/// [`Catalogue::read`] consumes.
///
/// The result names itself [`KEV_ID`] and carries CISA's `catalogVersion`, so scans run
/// against two dumps of the feed differ visibly in the report.
///
/// # Errors
///
/// [`KevError::Malformed`] for JSON that is not this feed, and
/// [`KevError::TooLarge`] past [`MAX_DOCUMENT_BYTES`].
pub fn to_document(input: &mut dyn BufRead) -> Result<String, KevError> {
    let feed = feed(input)?;
    let document = Document {
        id: KEV_ID.to_string(),
        version: catalogue_version(&feed.catalog_version),
        vulnerability: feed.vulnerabilities.iter().map(Entry::from).collect(),
    };

    // Serialised, never formatted by hand: a quote or backslash in CISA's strings would
    // otherwise change the document's structure.
    toml::to_string(&document).map_err(|error| KevError::Malformed(error.to_string()))
}

/// Reads the KEV JSON in `input` as a [`Catalogue`].
///
/// [`to_document`] and [`Catalogue::read`] in sequence. To re-run scans against the same
/// feed, convert once with [`to_document`] and keep the result.
///
/// # Errors
///
/// Everything [`to_document`] returns, and [`KevError::Rejected`] where the
/// document it produced was refused.
pub fn read(input: &mut dyn BufRead) -> Result<Catalogue, KevError> {
    let document = to_document(input)?;
    Ok(Catalogue::read(&mut document.as_bytes())?)
}

/// Reads the KEV JSON in `input` as the list of vulnerabilities it names
/// exploited, for marking what a correlation finds.
///
/// The use the feed's data fits best: KEV is keyed by CVE identifier, which a
/// correlation already has for every vulnerability it reports, so nothing here rests on
/// [`cpe_identity`]'s heuristic. The list names itself [`KEV_ID`] and carries CISA's
/// `catalogVersion`.
///
/// # Errors
///
/// [`KevError::Malformed`] for JSON that is not this feed,
/// [`KevError::TooLarge`] past [`MAX_DOCUMENT_BYTES`], and
/// [`KevError::Rejected`] where its version does not read as one.
pub fn exploited(input: &mut dyn BufRead) -> Result<KnownExploited, KevError> {
    let feed = feed(input)?;
    let version = catalogue_version(&feed.catalog_version);
    let version = version
        .parse()
        .map_err(|_| CatalogueError::UnreadableVersion { version })?;
    Ok(KnownExploited::new(
        KEV_ID,
        version,
        feed.vulnerabilities.into_iter().map(|entry| entry.cve_id),
    )?)
}

/// The feed in `input`, read no further than [`MAX_DOCUMENT_BYTES`].
fn feed(input: &mut dyn BufRead) -> Result<Feed, KevError> {
    // Bounded before the read, as `Catalogue::read` is: the feed comes from elsewhere.
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
    serde_json::from_str(&source).map_err(|error| KevError::Malformed(error.to_string()))
}

/// The identity a CPE would carry for a name KEV writes for a person.
///
/// Lower-cased, with runs of anything that is not alphanumeric, a hyphen, a dot
/// or an underscore collapsed to a single underscore. `HTTP Server` becomes
/// `http_server` and `D-Link` stays `d-link`, which are the identities CPE uses
/// for both.
///
/// A heuristic with no CPE dictionary behind it, so a product whose registered identity
/// is not its display name with the spaces replaced does not match:
/// `Adaptive Security Appliance (ASA)` normalises to `adaptive_security_appliance_asa`
/// where CPE says `adaptive_security_appliance`. Each such miss is a finding not raised,
/// never one raised wrongly.
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
/// The feed writes a date, `2026.09.03`, which becomes a version once the leading zeros
/// are dropped. Anything else is passed through for [`Catalogue::read`] to refuse.
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
            // The catalogue refuses an entry with no title; the CVE id is enough to look
            // one up.
            title: match entry.vulnerability_name.trim().is_empty() {
                true => format!("{} known exploited vulnerability", entry.cve_id),
                false => entry.vulnerability_name.clone(),
            },
            // Ransomware use is the only distinction the feed draws.
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
            // The feed has no version data; see the module documentation.
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

    /// Display names normalise to the CPE identities the correlator matches.
    #[test]
    fn a_display_name_becomes_the_identity_a_cpe_carries() {
        assert_eq!(cpe_identity("Apache"), "apache");
        assert_eq!(cpe_identity("HTTP Server"), "http_server");
        assert_eq!(cpe_identity("OpenBSD"), "openbsd");
        // CPE keeps the hyphen in this vendor's identity.
        assert_eq!(cpe_identity("D-Link"), "d-link");
        assert_eq!(cpe_identity("Windows Server 2019"), "windows_server_2019");
        // Runs of punctuation collapse to one separator.
        assert_eq!(cpe_identity("Foo   Bar"), "foo_bar");
        assert_eq!(cpe_identity("  Leading"), "leading");
        assert_eq!(cpe_identity(""), "");
    }

    /// The heuristic's known limit: a display name that is not the identity with its
    /// spaces replaced does not match.
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
        // Anything else is passed through for the catalogue reader to refuse.
        assert_eq!(catalogue_version("not-a-date"), "not-a-date");
    }

    /// The conversion produces a document the catalogue reader accepts.
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

    /// Severity comes from ransomware use: critical with it, high without, nothing
    /// lower.
    #[test]
    fn ransomware_use_is_the_one_distinction_the_feed_offers() {
        let document = to_document(&mut FEED.as_bytes()).expect("converts");
        assert!(
            document.contains(r#"severity = "critical""#),
            "the Citrix row"
        );
        assert!(document.contains(r#"severity = "high""#), "the Apache row");
    }

    /// A converted feed's correlation end to end. KEV names no version, so the entry
    /// matches a patched server as readily as a vulnerable one; the finding is `Weak`, and
    /// its excerpt does not claim a version was checked.
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

    /// A feed longer than the ceiling is refused without being buffered.
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

    /// Anything that is not the feed is refused; an empty catalogue would read as a scan
    /// that found nothing wrong.
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

    /// A name carrying TOML syntax does not become TOML structure. Two defences, for
    /// different fields: a vendor or product goes through [`cpe_identity`], which drops
    /// quotes and newlines; a title and a remediation are carried verbatim and are safe
    /// because the document is serialised.
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

        // Parsed, since both hostile strings survive as values inside multi-line strings,
        // which a line-based check would mistake for keys.
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

        // The severity this crate chose survived, not the one the hostile title set.
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
