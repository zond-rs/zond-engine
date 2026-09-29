// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Whether a CVE can reach the service it is keyed to
//!
//! A vulnerability database keys a flaw to the package it was fixed in, and a
//! package is more than its daemon. CVE-2023-38408 is a flaw in ssh-agent,
//! reached only through an agent someone forwarded to a hostile machine, and
//! NVD states it against `openbsd:openssh` exactly as it states regreSSHion. A
//! scan that found sshd listening can confirm the second and has no business
//! charging the host with the first.
//!
//! `assets/cve/applicability.toml` is the hand-written overlay that says which
//! is which, one CVE and one `vendor:product` at a time, and this module reads
//! it. The classes and the rule for choosing between them are stated in that
//! file's header, beside the entries they govern.
//!
//! Parsed once, on first use, from a copy compiled into the crate. A malformed
//! overlay is a defect in this crate rather than in anything a caller did, so
//! the tests below are what refuse one; a scan reading it treats a document
//! that does not parse as having no entries and correlates as it would without
//! the overlay, rather than failing.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::Deserialize;

/// The overlay as shipped.
const SOURCE: &str = include_str!("../../assets/cve/applicability.toml");

/// Where the code a CVE describes runs, relative to the listening service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Applies {
    /// The service itself, reachable over the network as it ships.
    Service,
    /// Only the client programs installed beside it: for OpenSSH, `ssh`, `scp`,
    /// `sftp`, `ssh-agent`, `ssh-add` and `ssh-keygen`.
    Client,
    /// Only someone who already holds an account on the host, or can write its
    /// configuration.
    Local,
    /// Only a service set up in a way it is not by default.
    Configuration {
        /// The setting it needs: a directive, or the module that must be
        /// loaded.
        requires: &'static str,
    },
}

/// What the overlay says about one CVE for one product.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Applicability {
    /// Where the flaw lives.
    pub(crate) applies: Applies,
    /// Why, as one short phrase a report can show beside the finding.
    pub(crate) reason: &'static str,
}

/// What the overlay says about `cve` as it affects `vendor_product`, the
/// catalogue's `vendor:product` key; [`None`] where it says nothing, which is
/// most CVEs and every product it does not cover.
///
/// Keyed by the product as well as the CVE because one CVE can name several
/// products and be a client flaw in one and a server flaw in another.
pub(crate) fn applicability(cve: &str, vendor_product: &str) -> Option<Applicability> {
    overlay()
        .get(cve)?
        .iter()
        .find(|stated| stated.product == vendor_product)
        .map(Stated::applicability)
}

/// The shipped overlay, parsed on first use, by CVE id.
///
/// Empty if it does not parse; see the module documentation for why that is
/// the tests' to refuse rather than a scan's.
fn overlay() -> &'static Overlay {
    static OVERLAY: OnceLock<Overlay> = OnceLock::new();
    OVERLAY.get_or_init(|| parse(SOURCE).unwrap_or_default())
}

/// Every entry, grouped by CVE.
type Overlay = HashMap<String, Vec<Stated>>;

/// One entry, validated and owned by the parsed overlay.
#[derive(Debug)]
struct Stated {
    product: String,
    applies: Class,
    reason: String,
}

/// [`Applies`], owning the setting a configuration entry names.
#[derive(Debug)]
enum Class {
    Service,
    Client,
    Local,
    Configuration(String),
}

impl Stated {
    /// The entry as the correlator reads it, borrowing from the overlay the
    /// process holds for its lifetime.
    fn applicability(&'static self) -> Applicability {
        Applicability {
            applies: match &self.applies {
                Class::Service => Applies::Service,
                Class::Client => Applies::Client,
                Class::Local => Applies::Local,
                Class::Configuration(requires) => Applies::Configuration { requires },
            },
            reason: &self.reason,
        }
    }
}

/// The document, as written.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    #[serde(default)]
    cve: Vec<Row>,
}

/// One `[[cve]]` table.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    id: String,
    product: String,
    applies: String,
    #[serde(default)]
    requires: Option<String>,
    reason: String,
}

/// Reads an overlay document, refusing one that says anything it cannot mean.
fn parse(source: &str) -> Result<Overlay, String> {
    let document: Document = toml::from_str(source).map_err(|error| error.to_string())?;

    let mut overlay = Overlay::new();
    for row in document.cve {
        let at = format!("{} for {}", row.id, row.product);
        if !is_cve_id(&row.id) {
            return Err(format!("{at}: not a CVE id"));
        }
        if row
            .product
            .split_once(':')
            .is_none_or(|(vendor, product)| vendor.is_empty() || product.is_empty())
        {
            return Err(format!("{at}: the product is not vendor:product"));
        }
        if row.reason.trim().is_empty() {
            return Err(format!("{at}: no reason given"));
        }

        let requires = row.requires.filter(|value| !value.trim().is_empty());
        let applies = match (row.applies.as_str(), requires) {
            ("service", None) => Class::Service,
            ("client", None) => Class::Client,
            ("local", None) => Class::Local,
            ("configuration", Some(requires)) => Class::Configuration(requires),
            // A setting on anything but a configuration entry is a class chosen
            // by mistake, and a configuration entry without one cannot say what
            // a reader should go and check.
            ("configuration", None) => return Err(format!("{at}: configuration needs requires")),
            ("service" | "client" | "local", Some(_)) => {
                return Err(format!("{at}: requires is only for configuration"));
            }
            (other, _) => return Err(format!("{at}: unknown applies value '{other}'")),
        };

        let products = overlay.entry(row.id).or_default();
        if products.iter().any(|stated| stated.product == row.product) {
            return Err(format!("{at}: stated twice"));
        }
        products.push(Stated {
            product: row.product,
            applies,
            reason: row.reason,
        });
    }
    Ok(overlay)
}

/// Whether `id` has the shape `CVE-<year>-<sequence>`.
fn is_cve_id(id: &str) -> bool {
    let Some((year, sequence)) = id
        .strip_prefix("CVE-")
        .and_then(|rest| rest.split_once('-'))
    else {
        return false;
    };
    year.len() == 4
        && sequence.len() >= 4
        && year.bytes().all(|byte| byte.is_ascii_digit())
        && sequence.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::cve::Catalogue;

    /// The CVEs the shipped catalogue holds for `vendor_product`, with the
    /// severities it gives them.
    fn catalogued(vendor_product: &str) -> BTreeSet<(String, String)> {
        let catalogue = Catalogue::embedded();
        let text = |index: u32| catalogue.pool[index as usize].as_str();
        catalogue
            .vulnerability
            .iter()
            .filter(|entry| {
                format!("{}:{}", text(entry.vendor), text(entry.product)) == vendor_product
            })
            .map(|entry| {
                (
                    text(entry.cve).to_string(),
                    text(entry.severity).to_string(),
                )
            })
            .collect()
    }

    /// The CVEs the overlay classifies for `vendor_product`.
    fn classified(vendor_product: &str) -> BTreeSet<String> {
        parse(SOURCE)
            .expect("the shipped overlay parses")
            .into_iter()
            .filter(|(_, products)| {
                products
                    .iter()
                    .any(|stated| stated.product == vendor_product)
            })
            .map(|(cve, _)| cve)
            .collect()
    }

    /// The shipped overlay parses, every value in it included.
    ///
    /// The one place a malformed overlay is caught. A scan reading one that
    /// does not parse carries on without it, which is the right thing for a
    /// scan to do and the wrong thing for a release to ship.
    #[test]
    fn the_shipped_overlay_parses() {
        let parsed = parse(SOURCE).expect("the shipped overlay parses");
        assert!(!parsed.is_empty());
        assert_eq!(overlay().len(), parsed.len());
    }

    /// Every OpenSSH CVE the catalogue carries has a class.
    ///
    /// OpenSSH is the package whose client flaws are most often charged to a
    /// listening daemon, and a regeneration that brings in a new one has to
    /// bring a decision about it too, or the correlator charges sshd with it
    /// by default.
    #[test]
    fn every_openssh_cve_in_the_catalogue_is_classified() {
        let classified = classified("openbsd:openssh");
        let missing: Vec<String> = catalogued("openbsd:openssh")
            .into_iter()
            .map(|(cve, _)| cve)
            .filter(|cve| !classified.contains(cve))
            .collect();
        assert!(
            missing.is_empty(),
            "the catalogue carries these OpenSSH CVEs and the overlay does not classify \
             them: {missing:?}"
        );
    }

    /// And every critical or high one for Apache HTTP Server, whose module
    /// flaws are the same problem: most of them need a module a default
    /// installation does not load.
    #[test]
    fn every_severe_apache_cve_in_the_catalogue_is_classified() {
        let classified = classified("apache:http_server");
        let missing: Vec<String> = catalogued("apache:http_server")
            .into_iter()
            .filter(|(_, severity)| matches!(severity.as_str(), "critical" | "high"))
            .map(|(cve, _)| cve)
            .filter(|cve| !classified.contains(cve))
            .collect();
        assert!(
            missing.is_empty(),
            "the catalogue carries these critical or high Apache HTTP Server CVEs and the \
             overlay does not classify them: {missing:?}"
        );
    }

    /// No entry names a CVE the catalogue does not carry for that product.
    ///
    /// An entry the catalogue has no row for can never be consulted, and is
    /// either a typo in the id or a product key the catalogue spells another
    /// way; both are silent without this.
    #[test]
    fn nothing_classified_is_missing_from_the_catalogue() {
        let parsed = parse(SOURCE).expect("the shipped overlay parses");
        let mut stray = Vec::new();
        for (cve, products) in &parsed {
            for stated in products {
                if !catalogued(&stated.product)
                    .iter()
                    .any(|(known, _)| known == cve)
                {
                    stray.push(format!("{cve} for {}", stated.product));
                }
            }
        }
        assert!(
            stray.is_empty(),
            "the overlay classifies these and the catalogue has no row for them: {stray:?}"
        );
    }

    /// The lookup answers for the CVE and the product together.
    #[test]
    fn a_classification_is_found_by_cve_and_product() {
        let agent = applicability("CVE-2023-38408", "openbsd:openssh").expect("classified");
        assert_eq!(agent.applies, Applies::Client);
        assert!(!agent.reason.is_empty());

        assert_eq!(
            applicability("CVE-2024-6387", "openbsd:openssh").map(|found| found.applies),
            Some(Applies::Service)
        );
        assert!(matches!(
            applicability("CVE-2021-40438", "apache:http_server").map(|found| found.applies),
            Some(Applies::Configuration {
                requires: "mod_proxy"
            })
        ));

        // The same id against a product it is not stated for says nothing.
        assert_eq!(applicability("CVE-2023-38408", "apache:http_server"), None);
        assert_eq!(applicability("CVE-1999-0000", "openbsd:openssh"), None);
    }

    /// An overlay that says something it cannot mean is refused, each way it
    /// can: a class that does not exist, a configuration that does not name
    /// its setting, a setting on a class that has none, a CVE stated twice
    /// for one product, a malformed id, and a field nobody reads.
    #[test]
    fn a_malformed_overlay_is_refused() {
        let row = |fields: &str| format!("[[cve]]\n{fields}\n");
        let valid = "id = \"CVE-2023-38408\"\nproduct = \"openbsd:openssh\"\n\
                     applies = \"client\"\nreason = \"agent\"";
        assert!(parse(&row(valid)).is_ok());

        for (fields, why) in [
            (
                "id = \"CVE-2023-38408\"\nproduct = \"openbsd:openssh\"\n\
                 applies = \"server\"\nreason = \"x\"",
                "unknown applies value",
            ),
            (
                "id = \"CVE-2023-38408\"\nproduct = \"openbsd:openssh\"\n\
                 applies = \"configuration\"\nreason = \"x\"",
                "configuration needs requires",
            ),
            (
                "id = \"CVE-2023-38408\"\nproduct = \"openbsd:openssh\"\n\
                 applies = \"client\"\nrequires = \"X11Forwarding yes\"\nreason = \"x\"",
                "requires is only for configuration",
            ),
            (
                "id = \"CVE-23-38408\"\nproduct = \"openbsd:openssh\"\n\
                 applies = \"client\"\nreason = \"x\"",
                "not a CVE id",
            ),
            (
                "id = \"CVE-2023-38408\"\nproduct = \"openssh\"\n\
                 applies = \"client\"\nreason = \"x\"",
                "not vendor:product",
            ),
            (
                "id = \"CVE-2023-38408\"\nproduct = \"openbsd:openssh\"\n\
                 applies = \"client\"\nreason = \" \"",
                "no reason given",
            ),
            (
                "id = \"CVE-2023-38408\"\nproduct = \"openbsd:openssh\"\n\
                 applies = \"client\"\nreason = \"x\"\nseverity = \"high\"",
                "unknown field",
            ),
        ] {
            let error = parse(&row(fields)).expect_err(why);
            assert!(error.contains(why), "{why}: {error}");
        }

        let error = parse(&format!("{}{}", row(valid), row(valid))).expect_err("stated twice");
        assert!(error.contains("stated twice"), "{error}");
    }
}
