// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # From a CPE to the source package a distribution builds it from
//!
//! A distribution files its security verdicts under its own source package
//! names, and a scan identifies software by CPE. `assets/cve/packages.toml` is
//! the join, written by hand for every product the fingerprint corpus can put
//! a version to; this module reads it once and answers one question: under
//! which name does this distributor publish verdicts for this product, in this
//! release, at this upstream version.
//!
//! The upstream version is part of the question because a release can carry
//! several series of one product side by side, each built from a source
//! package of its own: Ubuntu 14.04 ships `mysql-5.5` and `mysql-5.6`, Debian
//! 12 `tomcat9` and `tomcat10`. Answering by release alone would pick one of
//! them for both, and a fix version from one series compared with a build of
//! the other says nothing true: Tomcat 10 would read as carrying every fix
//! made to Tomcat 9.
//!
//! The same map bounds what the advisory converters keep. A distribution's
//! feed covers thousands of source packages and a scan can only ever ask
//! about these, so converting the rest would cost memory and time for data
//! nothing reads.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;

/// The map as written, one entry per `vendor:product`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    product: BTreeMap<String, Product>,
}

/// One product's source package at each distributor that builds it. A
/// distributor left out does not.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Product {
    ubuntu: Option<Spec>,
    debian: Option<Spec>,
}

impl Product {
    fn at(&self, distributor: &str) -> Option<&Spec> {
        match distributor {
            "ubuntu" => self.ubuntu.as_ref(),
            "debian" => self.debian.as_ref(),
            _ => None,
        }
    }
}

/// How one distributor names a product's source package.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Spec {
    /// One name in every release and at every version.
    Always(String),
    /// Rules tried in order, the first that holds naming the package.
    Rules(Vec<Rule>),
}

impl Spec {
    fn package(&self, release: &str, upstream: &str) -> Option<&str> {
        match self {
            Self::Always(package) => Some(package),
            Self::Rules(rules) => rules
                .iter()
                .find(|rule| rule.holds(release, upstream))
                .map(|rule| rule.package.as_str()),
        }
    }

    /// Every package name the spec can answer with.
    fn packages(&self) -> Vec<&str> {
        match self {
            Self::Always(package) => vec![package.as_str()],
            Self::Rules(rules) => rules.iter().map(|rule| rule.package.as_str()).collect(),
        }
    }
}

/// A source package that applies in one release, to one upstream series, or
/// both; a rule naming neither applies always.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    release: Option<String>,
    series: Option<String>,
    package: String,
}

impl Rule {
    fn holds(&self, release: &str, upstream: &str) -> bool {
        self.release.as_deref().is_none_or(|r| r == release)
            && self
                .series
                .as_deref()
                .is_none_or(|series| in_series(upstream, series))
    }
}

/// Whether an upstream version belongs to a series: it starts with the series
/// and does not continue it with another digit, so `9` holds for `9.0.58` and
/// for `9`, and not for `90.1`.
fn in_series(upstream: &str, series: &str) -> bool {
    upstream
        .strip_prefix(series)
        .is_some_and(|rest| !rest.starts_with(|c: char| c.is_ascii_digit()))
}

/// The shipped map, parsed on first use.
fn document() -> &'static Document {
    static DOCUMENT: OnceLock<Document> = OnceLock::new();
    DOCUMENT.get_or_init(|| {
        toml::from_str(include_str!("../../assets/cve/packages.toml"))
            .expect("the shipped source package map parses, which the tests below pin")
    })
}

/// The source package `distributor` files its verdicts on `vendor_product`
/// under, for a build of upstream version `upstream` in `release`.
///
/// `distributor` is `"ubuntu"` or `"debian"`; `release` is the release number
/// as the distributor gives it (`"14.04"`, `"12"`), never a codename.
/// [`None`] where the distributor does not package the product, or packages no
/// series `upstream` belongs to.
#[allow(dead_code)]
pub(crate) fn source_package(
    vendor_product: &str,
    distributor: &str,
    release: &str,
    upstream: &str,
) -> Option<&'static str> {
    document()
        .product
        .get(vendor_product)?
        .at(distributor)?
        .package(release, upstream)
}

/// Every source package name the map gives `distributor`, over all products,
/// releases and series: the packages whose advisories a scan can ever ask
/// about.
#[cfg_attr(not(feature = "import-distro"), allow(dead_code))]
pub(crate) fn source_packages(distributor: &str) -> impl Iterator<Item = &'static str> + '_ {
    document()
        .product
        .values()
        .filter_map(move |product| product.at(distributor))
        .flat_map(Spec::packages)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// Products the fingerprint corpus can version that no distributor this
    /// map covers builds, with the reason.
    ///
    /// Checked in both directions like the catalogue's own exemptions: a
    /// product that gains a package has to leave this list, and an entry for a
    /// product the corpus no longer versions has to go.
    const NOT_PACKAGED: &[(&str, &str)] = &[
        ("aerospike:aerospike_server", "vendor distribution only"),
        ("altn:mdaemon", "proprietary Windows server"),
        ("amazon:elastic_load_balancing", "hosted service"),
        ("analogx:proxy", "proprietary Windows software"),
        ("apache:james", "not in Debian or Ubuntu"),
        ("aprelium:abyss_web_server_x1", "proprietary server"),
        ("argosoft:mail_server", "proprietary Windows server"),
        ("aspen:aspen", "not in Debian or Ubuntu"),
        ("attachmate:reflection_for_secure_it", "proprietary server"),
        (
            "avaya:aura_communication_manager",
            "vendor appliance firmware",
        ),
        ("avocent:dsview", "vendor appliance software"),
        ("axway:securetransport", "proprietary server"),
        ("ballerina:ballerina", "not in Debian or Ubuntu"),
        ("bea:weblogic_server", "proprietary server"),
        ("bftpd_project:bftpd", "not in Debian or Ubuntu"),
        (
            "boa:boa",
            "left Debian and Ubuntu before any release their fix data covers",
        ),
        ("caucho:resin", "not in Debian or Ubuntu"),
        ("citrix:netscaler", "vendor appliance firmware"),
        ("citrix:xenserver", "vendor hypervisor platform"),
        ("communigate:communigate_pro", "proprietary server"),
        ("connectwise:control", "proprietary server"),
        ("couchbase:sync_gateway", "vendor distribution only"),
        ("cpanel:cpanel", "proprietary control panel"),
        ("crowcpp:crow", "not in Debian or Ubuntu"),
        (
            "embedthis:appweb",
            "left Debian and Ubuntu before any release their fix data covers",
        ),
        (
            "f5:big-ip_local_traffic_manager",
            "vendor appliance firmware",
        ),
        (
            "filezilla-project:filezilla_server",
            "Windows server; Debian and Ubuntu package the client only",
        ),
        ("fortinet:fortivoice", "vendor appliance firmware"),
        ("freeswitch:freeswitch", "vendor repository only"),
        (
            "helpsystems:goanywhere_managed_file_transfer",
            "proprietary server",
        ),
        ("hp:web_jetadmin", "proprietary Windows software"),
        (
            "hydra_project:hydra",
            "not in Debian or Ubuntu; their `hydra` is the password auditor",
        ),
        ("ibm:lotus_domino", "proprietary server"),
        ("ibm:security_directory_server", "proprietary server"),
        ("ibm:websphere", "proprietary server"),
        ("intel:standard_manageability", "platform firmware"),
        ("ipswitch:imail_server", "proprietary Windows server"),
        ("ipswitch:moveit_dmz", "proprietary Windows server"),
        ("ipswitch:ws_ftp", "proprietary Windows server"),
        ("jamf:jamf", "proprietary server"),
        ("jellyfin:jellyfin", "vendor repository only"),
        ("jfrog:artifactory", "proprietary server"),
        ("konghq:kong_gateway", "vendor repository only"),
        (
            "litespeedtech:litespeed_web_server",
            "vendor distribution only",
        ),
        ("mailenable:mailenable", "proprietary Windows server"),
        ("mcafee:webshield", "vendor appliance software"),
        ("microsoft:exchange_server", "Windows server"),
        ("microsoft:internet_information_services", "Windows server"),
        ("microsoft:personal_web_server", "Windows server"),
        ("microsoft:sql_server", "vendor repository only"),
        (
            "mongrel:mongrel",
            "left Debian and Ubuntu before any release their fix data covers",
        ),
        (
            "netscape:commerce_server",
            "discontinued proprietary server",
        ),
        (
            "netscape:directory_server",
            "discontinued proprietary server",
        ),
        (
            "netscape:fasttrack_server",
            "discontinued proprietary server",
        ),
        (
            "netscape:messaging_server",
            "discontinued proprietary server",
        ),
        ("netwin:surgeftp", "proprietary server"),
        ("nortel:callpilot", "vendor appliance software"),
        ("novell:edirectory", "proprietary server"),
        ("novell:groupwise", "proprietary server"),
        ("novell:netware_enterprise_web_server", "NetWare server"),
        ("openresty:openresty", "vendor repository only"),
        ("oracle:application_server", "proprietary server"),
        ("oracle:application_server_portal", "proprietary server"),
        ("oracle:application_server_web_cache", "proprietary server"),
        ("oracle:http_server", "proprietary server"),
        ("oracle:iplanet_web_server", "proprietary server"),
        ("oracle:web_cache", "proprietary server"),
        (
            "parallels:parallels_plesk_panel",
            "proprietary control panel",
        ),
        ("pi-hole:pi-hole", "vendor installer only"),
        ("qdpm:qdpm", "not in Debian or Ubuntu"),
        ("realvnc:realvnc", "proprietary server"),
        ("redhat:directory_server", "Red Hat product"),
        (
            "redhat:jboss_enterprise_application_platform",
            "Red Hat product",
        ),
        (
            "redhat:jboss_wildfly_application_server",
            "not in Debian or Ubuntu",
        ),
        ("redhat:wildfly", "not in Debian or Ubuntu"),
        (
            "sap:netweaver_application_server_abap",
            "proprietary server",
        ),
        (
            "sap:netweaver_application_server_java",
            "proprietary server",
        ),
        ("sap:sql_anywhere", "proprietary server"),
        ("solarwinds:serv-u_ftp_server", "proprietary server"),
        ("sonicwall:email_security", "vendor appliance firmware"),
        (
            "sonicwall:universal_management_appliance",
            "vendor appliance firmware",
        ),
        ("ssh:tectia_server", "proprietary server"),
        (
            "sun:java_system_application_server",
            "discontinued proprietary server",
        ),
        (
            "sun:java_system_web_proxy_server",
            "discontinued proprietary server",
        ),
        (
            "sun:java_system_web_server",
            "discontinued proprietary server",
        ),
        ("teamspeak:teamspeak", "proprietary server"),
        ("treck:tcp%2fip", "embedded stack in vendor firmware"),
        ("tridium:niagara_ax", "vendor appliance software"),
        ("vandyke:vshell", "proprietary server"),
        ("wftpserver:wing_ftp_server", "proprietary server"),
        ("wowza:streaming_engine", "proprietary server"),
        ("xiongmaitech:uc-httpd", "vendor appliance firmware"),
        ("zimbra:collaboration", "vendor distribution only"),
    ];

    fn versioned() -> &'static BTreeSet<String> {
        crate::fingerprint::SignatureDb::global().versioned_products()
    }

    /// Every product a scan can put a version to is either mapped to a source
    /// package or listed as not packaged, with the reason.
    ///
    /// A gap is silent: the banner names an Ubuntu build, the distributor
    /// published a verdict for it, and nothing joins the two, so the report
    /// keeps the upstream range's false positive with no sign that a better
    /// answer was on hand.
    #[test]
    fn every_versioned_product_is_mapped_or_listed_as_not_packaged() {
        let mapped = &document().product;
        let listed: BTreeSet<&str> = NOT_PACKAGED.iter().map(|(key, _)| *key).collect();

        let unexplained: Vec<&String> = versioned()
            .iter()
            .filter(|key| !mapped.contains_key(*key) && !listed.contains(key.as_str()))
            .collect();
        assert!(
            unexplained.is_empty(),
            "the corpus can version these and nothing says which source package builds them: \
             {unexplained:?}. Map them in assets/cve/packages.toml or list them in NOT_PACKAGED \
             with the reason."
        );

        let both: Vec<&&str> = listed
            .iter()
            .filter(|key| mapped.contains_key(**key))
            .collect();
        assert!(
            both.is_empty(),
            "mapped and listed as not packaged at once: {both:?}"
        );
    }

    /// And the other direction: no entry in the map or on the list names a
    /// product the corpus cannot version, so neither can outlive a corpus
    /// change or hide a misspelt key that matches nothing.
    #[test]
    fn nothing_mapped_or_listed_names_a_product_the_corpus_cannot_version() {
        let versioned = versioned();
        let stale: Vec<&str> = document()
            .product
            .keys()
            .map(String::as_str)
            .chain(NOT_PACKAGED.iter().map(|(key, _)| *key))
            .filter(|key| !versioned.contains(*key))
            .collect();

        assert!(
            stale.is_empty(),
            "these name products the corpus cannot put a version to: {stale:?}. Correct the \
             identifier or remove the entry."
        );
    }

    /// Every rule in the map can be reached and names a package the way a
    /// distributor spells one: a catch-all rule before another hides it, and
    /// a release written as a codename never matches the numbers the lookup
    /// is given.
    #[test]
    fn every_rule_is_reachable_and_well_formed() {
        let package_name = |name: &str| {
            name.len() >= 2
                && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "+-.".contains(c))
        };
        let release_number = |release: &str| {
            release == "sid"
                || release
                    .split('.')
                    .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        };

        for (product, entry) in &document().product {
            assert!(
                entry.ubuntu.is_some() || entry.debian.is_some(),
                "{product} maps to no distributor; list it as not packaged instead"
            );
            for (distributor, spec) in [("ubuntu", &entry.ubuntu), ("debian", &entry.debian)] {
                let Some(spec) = spec else { continue };
                for package in spec.packages() {
                    assert!(
                        package_name(package),
                        "{product} at {distributor}: {package:?}"
                    );
                }
                let Spec::Rules(rules) = spec else { continue };
                assert!(!rules.is_empty(), "{product} at {distributor} has no rules");
                for (index, rule) in rules.iter().enumerate() {
                    if let Some(release) = &rule.release {
                        assert!(release_number(release), "{product}: release {release:?}");
                    }
                    let catch_all = rule.release.is_none() && rule.series.is_none();
                    assert!(
                        !catch_all || index == rules.len() - 1,
                        "{product} at {distributor}: a rule that always holds hides the rules after it"
                    );
                }
            }
        }
    }

    /// A release that carries several series of a product answers by the
    /// series the build belongs to, so a fix in one is never read as a fix in
    /// the other.
    #[test]
    fn parallel_series_in_one_release_map_to_their_own_packages() {
        assert_eq!(
            source_package("oracle:mysql", "ubuntu", "14.04", "5.5.62"),
            Some("mysql-5.5")
        );
        assert_eq!(
            source_package("oracle:mysql", "ubuntu", "14.04", "5.6.33"),
            Some("mysql-5.6")
        );
        assert_eq!(
            source_package("apache:tomcat", "debian", "12", "9.0.70"),
            Some("tomcat9")
        );
        assert_eq!(
            source_package("apache:tomcat", "debian", "12", "10.1.6"),
            Some("tomcat10")
        );
        // `1` is not the start of a `10` series.
        assert_eq!(source_package("apache:tomcat", "debian", "12", "1.0"), None);
    }

    /// A release rule applies in its release alone, and the rule after it
    /// answers everywhere else.
    #[test]
    fn a_release_rule_applies_in_that_release_alone() {
        assert_eq!(
            source_package("tornadoweb:tornado", "ubuntu", "20.04", "4.5.3"),
            Some("python-tornado4")
        );
        assert_eq!(
            source_package("tornadoweb:tornado", "ubuntu", "18.04", "4.5.3"),
            Some("python-tornado")
        );
        assert_eq!(
            source_package("ruby-lang:webrick", "ubuntu", "18.04", "1.4.2"),
            Some("ruby2.5")
        );
        assert_eq!(
            source_package("ruby-lang:webrick", "ubuntu", "22.04", "1.7.0"),
            Some("ruby-webrick")
        );
    }

    /// The names the correlator asks about most, and the answers for what no
    /// distributor builds.
    #[test]
    fn a_product_maps_to_its_source_package_and_an_unpackaged_one_to_none() {
        assert_eq!(
            source_package("openbsd:openssh", "ubuntu", "14.04", "6.6.1p1"),
            Some("openssh")
        );
        assert_eq!(
            source_package("apache:http_server", "debian", "12", "2.4.62"),
            Some("apache2")
        );
        assert_eq!(
            source_package("squid-cache:squid", "ubuntu", "16.04", "3.5.12"),
            Some("squid3")
        );
        assert_eq!(
            source_package("squid-cache:squid", "ubuntu", "22.04", "5.9"),
            Some("squid")
        );
        assert_eq!(
            source_package("proftpd:proftpd", "debian", "12", "1.3.8"),
            Some("proftpd-dfsg")
        );
        assert_eq!(
            source_package("elastic:elasticsearch", "debian", "12", "7.0"),
            None
        );
        assert_eq!(
            source_package(
                "microsoft:internet_information_services",
                "ubuntu",
                "22.04",
                "10.0"
            ),
            None
        );
        assert_eq!(
            source_package("openbsd:openssh", "fedora", "40", "9.6p1"),
            None
        );
    }

    /// The package list the converters keep is the map's, every series and
    /// release included.
    #[test]
    fn the_package_list_holds_every_name_the_map_gives() {
        let ubuntu: BTreeSet<&str> = source_packages("ubuntu").collect();
        for name in [
            "openssh",
            "apache2",
            "php5",
            "php8.3",
            "mysql-5.5",
            "python-tornado4",
        ] {
            assert!(ubuntu.contains(name), "{name}");
        }
        let debian: BTreeSet<&str> = source_packages("debian").collect();
        assert!(debian.contains("tomcat10") && debian.contains("proftpd-dfsg"));
        assert!(!debian.contains("glassfish"));
        assert_eq!(source_packages("fedora").count(), 0);
    }
}
