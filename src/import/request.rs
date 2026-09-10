// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # One scan, described as a document
//!
//! What to scan and how, written down rather than assembled by setting fields.
//! [`import::settings`](crate::import::settings) covers the values worth setting
//! once and keeping; this covers the ones that change from run to run, and it
//! covers the targets, which a settings file has no business naming.
//!
//! ```toml
//! targets = ["10.0.0.0/24", "db.internal"]
//! exclude = ["10.0.0.7"]
//! ports = "1-1024,8080"
//!
//! service_detection = "thorough"
//! os_detection = "active"
//! traceroute = true
//!
//! [settings]
//! effort = "balanced"
//! host_timeout = 60
//!
//! [evasion]
//! source_port = 53
//! ttl = 12
//! ```
//!
//! The same document in JSON, or in anything else `serde` reads, since
//! [`ScanRequest`] is an ordinary deserializable struct and this module opens no
//! files and names no format:
//!
//! ```
//! # #[cfg(feature = "import-json")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use zond_engine::import::request::ScanRequest;
//!
//! let request: ScanRequest = serde_json::from_str(r#"{
//!     "targets": ["192.0.2.0/24"],
//!     "ports": "22,80,443",
//!     "service_detection": "thorough"
//! }"#)?;
//!
//! assert_eq!(request.targets.len(), 1);
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "import-json"))]
//! # fn main() {}
//! ```
//!
//! ## Where it sits in the layering
//!
//! `import::settings` describes a chain, each layer overriding the one before:
//!
//! ```text
//! ZondConfig::default()  →  system file  →  user file  →  named profile  →  the caller
//! ```
//!
//! A request is the last arrow. It is applied after everything a settings file
//! said and overrides it, because it was written for this run by whoever is
//! starting it. That position is why it may do two things a settings file may
//! not: name targets, and widen a scan.
//!
//! ## An unknown key is refused, not warned about
//!
//! The opposite of [`SettingsWarning`](crate::import::settings::SettingsWarning),
//! and for the reason that makes a warning right there. A settings file outlives
//! the engine that reads it, so an older build must be able to read a profile a
//! colleague wrote with a newer one, and refusing would turn a shared file into a
//! version lock. A request has no such life: it is written now, applied once, and
//! whoever wrote it is holding the error. So `deny_unknown_fields` refuses a
//! misspelled key by naming what would have worked, which is the answer a caller
//! composing a request can act on.
//!
//! The `[settings]` table inside a request keeps the settings document's own
//! rule, since it is that document's type. A key nobody knows there is ignored
//! rather than refused, and [`settings::parse`](crate::import::settings::parse)
//! is the reader that reports them.
//!
//! ## Two steps, because one of them touches the network
//!
//! [`apply_to`](ScanRequest::apply_to) writes the settings into a
//! [`ZondConfig`]. It is synchronous, total, and reads nothing outside the
//! request.
//!
//! [`resolve`](ScanRequest::resolve) turns the target and exclusion expressions
//! into addresses. It reads this host's interface table for `lan` and for the
//! `%interface` suffix, and it may send DNS queries, so it is asynchronous and
//! fallible and the caller decides when to take it. Target expressions are held
//! as written for the same reason
//! [`default_ports`](crate::import::settings::Settings::default_ports) is: a
//! target is a grammar, and a struct that parsed one on the way in would be
//! doing lookups inside `Deserialize`.

use std::collections::BTreeSet;
use std::net::IpAddr;

use serde::Deserialize;

use crate::config::envelope::DetectionEnvelope;
use crate::config::{IdleScan, OsDetection, ServiceDetection, ZondConfig};
use crate::evasion::EvasionProfile;
use crate::import::settings::{Settings, de_named};
use crate::model::exclusion::Exclusions;
use crate::model::ip::set::IpSet;
use crate::model::mac::MacAddr;
use crate::model::parse::target::TargetParseError;
use crate::model::port::PortSet;
use crate::resolve::{self, DiscoveryTargets, Resolver};

/// What went wrong turning a request into a scan.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    /// A target or exclusion expression could not be read.
    #[error("{0}")]
    Targets(#[from] TargetParseError),

    /// The port specification was not a valid one.
    #[error("ports = '{spec}': {reason}")]
    Ports {
        /// What was written.
        spec: String,
        /// Why it was refused.
        reason: String,
    },

    /// The request named nothing to scan.
    #[error("the request names no targets")]
    NoTargets,
}

/// One scan, as a document.
///
/// Every field is optional and silence means the value already in the
/// [`ZondConfig`] stands, which is what makes a request a layer rather than a
/// replacement. See the module documentation for where that layer sits.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanRequest {
    /// What to scan, in the target grammar: addresses, ranges, CIDR blocks,
    /// hostnames, `lan`, and a `%interface` suffix on a link-local address.
    ///
    /// Held as written. [`resolve`](Self::resolve) reads them.
    pub targets: Vec<String>,

    /// What this scan may not probe, in the same grammar as `targets`.
    ///
    /// The full grammar, unlike a settings file's `exclude`, which takes literal
    /// addresses only. A settings file is written once and read on machines
    /// where `lan` and `db.internal` mean something else; a request is resolved
    /// on the machine that will run the scan, moments after it was written.
    ///
    /// Added to whatever the configuration already forbids rather than replacing
    /// it, so applying a request cannot drop an exclusion a settings file set.
    pub exclude: Vec<String>,

    /// The ports to scan, in the [`PortSet`] grammar: `22`, `1-1024`,
    /// `U:53,161`, `T:80,443`.
    ///
    /// Held as written, and parsed by [`ports`](Self::ports). Falls back to the
    /// `[settings]` table's `default_ports` when the request names none.
    pub ports: Option<String>,

    /// The values a settings file could also have set.
    ///
    /// Present so one document can carry a whole scan. A request that names
    /// nothing here layers over whatever was loaded from disk; one that does
    /// overrides it, since a request is the later layer.
    pub settings: Settings,

    /// Treats every target as reachable and goes straight to the ports.
    pub assume_up: Option<bool>,

    /// Measures the path to each host that answered.
    pub traceroute: Option<bool>,

    /// Reads what a host's stack and services reveal about it beyond which ports
    /// are open.
    pub characterise: Option<bool>,

    /// Keeps the ICMP messages a probe drew as evidence in the report, rather
    /// than only the verdict they settled.
    pub icmp_evidence: Option<bool>,

    /// The IP protocol numbers to ask each host about, one layer below the
    /// ports. Replaces the set rather than adding to it.
    pub ip_protocols: Option<BTreeSet<u8>>,

    /// The addresses to send every probe from, overriding what the routing table
    /// would choose. At most one per family is used, and an empty list gives the
    /// choice back to the host. Replaces the list rather than adding to it.
    pub send_source: Option<Vec<IpAddr>>,

    /// How far to go establishing the operating system: `off`, `passive`,
    /// `active` or `aggressive`.
    #[serde(deserialize_with = "de_named")]
    pub os_detection: Option<OsDetection>,

    /// How far to go identifying what is behind each open port: `off`, `banner`,
    /// `probe` or `thorough`.
    #[serde(deserialize_with = "de_named")]
    pub service_detection: Option<ServiceDetection>,

    /// The most intrusive class of detection this scan may run.
    #[serde(deserialize_with = "de_named")]
    pub detection: Option<DetectionEnvelope>,

    /// Scans through a third host rather than from this one.
    #[serde(deserialize_with = "de_idle_scan")]
    pub idle_scan: Option<IdleScan>,

    /// How probes are shaped to get past a filter.
    ///
    /// Replaces the profile outright rather than layering field by field. An
    /// evasion profile is one posture, and half of one taken from a settings file
    /// and half from a request would be a posture nobody chose. Refused at read
    /// time if [`EvasionProfile::validate`] rejects it.
    #[serde(deserialize_with = "de_evasion")]
    pub evasion: Option<EvasionProfile>,
}

impl ScanRequest {
    /// A request that changes nothing and names no targets.
    pub fn new() -> Self {
        Self::default()
    }

    /// The port set this request scans, if it settles one.
    ///
    /// The request's own `ports` first, then the `[settings]` table's
    /// `default_ports`. [`None`] when neither names any, which leaves the choice
    /// to whatever the caller was going to use.
    ///
    /// # Errors
    ///
    /// [`RequestError::Ports`] if the specification is malformed. Separate from
    /// the field so that a request is worth reading even when one key in it is
    /// wrong.
    pub fn ports(&self) -> Option<Result<PortSet, RequestError>> {
        if let Some(spec) = self.ports.as_deref() {
            return Some(
                PortSet::try_from(spec).map_err(|error| RequestError::Ports {
                    spec: spec.to_string(),
                    reason: error.to_string(),
                }),
            );
        }

        self.settings.ports().map(|parsed| {
            parsed.map_err(|error| RequestError::Ports {
                spec: self.settings.default_ports.clone().unwrap_or_default(),
                reason: error.to_string(),
            })
        })
    }

    /// Applies everything this request says to `config`, leaving the rest as it
    /// was.
    ///
    /// The `[settings]` table goes on first and the request's own fields
    /// override it, so a document that says `effort = "thorough"` under
    /// `[settings]` and `service_detection = "off"` at the top level means both.
    ///
    /// Targets are not applied here. They are addresses rather than settings and
    /// they need [`resolve`](Self::resolve) first.
    pub fn apply_to(&self, config: &mut ZondConfig) {
        self.settings.apply_to(config);

        if let Some(value) = self.assume_up {
            config.assume_up = value;
        }
        if let Some(value) = self.traceroute {
            config.traceroute = value;
        }
        if let Some(value) = self.characterise {
            config.characterise = value;
        }
        if let Some(value) = self.icmp_evidence {
            config.icmp_evidence = value;
        }
        if let Some(protocols) = &self.ip_protocols {
            config.ip_protocols = protocols.clone();
        }
        if let Some(sources) = &self.send_source {
            config.send_source = sources.clone();
        }
        if let Some(value) = self.os_detection {
            config.os_detection = value;
        }
        if let Some(value) = self.service_detection {
            config.service_detection = value;
        }
        if let Some(value) = self.detection {
            config.detection = value;
        }
        if self.idle_scan.is_some() {
            config.idle_scan = self.idle_scan;
        }
        if let Some(profile) = &self.evasion {
            config.evasion = profile.clone();
        }
    }

    /// Resolves the target and exclusion expressions into addresses.
    ///
    /// `names` is the DNS policy and it is the caller's, exactly as it is on
    /// [`resolve::for_discovery`]: [`Some`] resolves hostnames, and [`None`]
    /// refuses them, which is what a scan running under
    /// [`no_dns`](ZondConfig::no_dns) needs.
    ///
    /// # Errors
    ///
    /// [`RequestError::NoTargets`] if the request names none, and
    /// [`RequestError::Targets`] if an expression cannot be read or a hostname
    /// does not resolve.
    pub async fn resolve(&self, names: Option<&Resolver>) -> Result<Resolved, RequestError> {
        if self.targets.is_empty() {
            return Err(RequestError::NoTargets);
        }

        let targets = resolve::for_discovery(&self.targets, names).await?;
        let exclude = if self.exclude.is_empty() {
            Exclusions::none()
        } else {
            resolve::for_exclusion(&self.exclude, names).await?
        };
        let ports = self.ports().transpose()?;

        Ok(Resolved {
            targets,
            exclude,
            ports,
        })
    }
}

/// What a request's expressions turned out to mean.
///
/// Produced by [`ScanRequest::resolve`]. The addresses go to
/// [`discover`](crate::scanner::discover); the exclusions and the sweep flag go
/// to the configuration through [`apply_to`](Self::apply_to).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Resolved {
    targets: DiscoveryTargets,
    exclude: Exclusions,
    ports: Option<PortSet>,
}

impl Resolved {
    /// The addresses to probe.
    pub fn ips(&self) -> &IpSet {
        self.targets.ips()
    }

    /// Takes the addresses, for handing to [`discover`](crate::scanner::discover).
    pub fn into_ips(self) -> IpSet {
        self.targets.into_ips()
    }

    /// The ports the request settled on, if it settled any.
    pub fn ports(&self) -> Option<&PortSet> {
        self.ports.as_ref()
    }

    /// The addresses this scan may not probe.
    pub fn exclusions(&self) -> &Exclusions {
        &self.exclude
    }

    /// Takes both halves, for a caller building a
    /// [`TargetMap`](crate::model::target::TargetMap) of its own.
    pub fn into_parts(self) -> (IpSet, Option<PortSet>) {
        (self.targets.into_ips(), self.ports)
    }

    /// Writes what these targets imply into `config`.
    ///
    /// The exclusions, and whether a network was named rather than a set of
    /// addresses. Exclusions are added to what `config` already forbids, so the
    /// order a caller applies a request and a settings file in cannot lose
    /// either one's scope.
    pub fn apply_to(&self, config: &mut ZondConfig) {
        self.targets.apply_to(config);
        config.exclusions.extend(&self.exclude);
    }
}

// ---------------------------------------------------------------------------
// Deserialization of the fields that are tables of their own
// ---------------------------------------------------------------------------

/// The document form of [`IdleScan`], which carries no `Deserialize` of its own.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdleScanDocument {
    zombie: IpAddr,
    #[serde(default)]
    zombie_port: Option<u16>,
}

/// Reads an `[idle_scan]` table.
fn de_idle_scan<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<IdleScan>, D::Error> {
    let Some(document) = Option::<IdleScanDocument>::deserialize(d)? else {
        return Ok(None);
    };

    Ok(Some(IdleScan {
        zombie: document.zombie,
        zombie_port: document.zombie_port,
    }))
}

/// The document form of [`EvasionProfile`].
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct EvasionDocument {
    source_port: Option<u16>,
    ttl: Option<u8>,
    padding: Option<u16>,
    bad_tcp_checksum: bool,
    #[serde(deserialize_with = "de_named")]
    spoof_mac: Option<MacAddr>,
    fragment: Option<u16>,
    decoys: Vec<IpAddr>,
    /// The TCP flag byte, as the constants in
    /// [`protocols::tcp::flags`](crate::protocols::tcp::flags) name it.
    flags: Option<u8>,
}

/// Reads an `[evasion]` table, refusing a profile the engine would refuse later.
fn de_evasion<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<EvasionProfile>, D::Error> {
    let Some(document) = Option::<EvasionDocument>::deserialize(d)? else {
        return Ok(None);
    };

    let profile = EvasionProfile {
        source_port: document.source_port,
        ttl: document.ttl,
        padding: document.padding,
        bad_tcp_checksum: document.bad_tcp_checksum,
        spoof_mac: document.spoof_mac,
        fragment: document.fragment,
        decoys: document.decoys,
        flags: document.flags,
    };

    profile.validate().map_err(serde::de::Error::custom)?;

    Ok(Some(profile))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScanEffort;
    use crate::model::finding::DetectionClass;
    use crate::model::technique::TcpScanTechnique;

    /// Reads a request the way a caller would, and fails naming what stopped it.
    fn request(document: &str) -> ScanRequest {
        toml::from_str(document).expect("the document is a request")
    }

    /// A configuration with nothing at its default, so anything a request
    /// overwrites is visible.
    fn settled() -> ZondConfig {
        ZondConfig {
            assume_up: true,
            traceroute: true,
            characterise: true,
            icmp_evidence: true,
            os_detection: OsDetection::Aggressive,
            service_detection: ServiceDetection::Thorough,
            tcp_technique: TcpScanTechnique::Fin,
            send_source: vec!["198.51.100.1".parse().expect("literal")],
            ..Default::default()
        }
    }

    /// The whole reason every field is an `Option`. A request layers over a
    /// configuration somebody else built, and silence has to mean silence.
    #[test]
    fn a_request_that_says_nothing_changes_no_setting() {
        let mut config = settled();
        ScanRequest::new().apply_to(&mut config);

        assert!(config.assume_up);
        assert!(config.traceroute);
        assert!(config.characterise);
        assert!(config.icmp_evidence);
        assert_eq!(config.os_detection, OsDetection::Aggressive);
        assert_eq!(config.service_detection, ServiceDetection::Thorough);
        assert_eq!(config.tcp_technique, TcpScanTechnique::Fin);
        assert_eq!(config.send_source, settled().send_source);
        assert!(config.idle_scan.is_none());
        assert!(!config.evasion.is_active());
    }

    #[test]
    fn every_key_a_request_understands_reaches_the_configuration() {
        let request = request(
            r#"
            targets = ["192.0.2.0/24"]
            ports = "22,80"
            assume_up = false
            traceroute = false
            characterise = false
            icmp_evidence = false
            ip_protocols = [1, 47, 50]
            send_source = ["192.0.2.2"]
            os_detection = "passive"
            service_detection = "banner"
            detection = "exploit"

            [settings]
            effort = "single"
            tcp_technique = "syn"

            [idle_scan]
            zombie = "192.0.2.9"
            zombie_port = 445

            [evasion]
            source_port = 53
            ttl = 12
            decoys = ["192.0.2.5"]
            "#,
        );

        let mut config = settled();
        request.apply_to(&mut config);

        assert!(!config.assume_up);
        assert!(!config.traceroute);
        assert!(!config.characterise);
        assert!(!config.icmp_evidence);
        assert_eq!(config.ip_protocols, BTreeSet::from([1, 47, 50]));
        assert_eq!(
            config.send_source,
            vec!["192.0.2.2".parse::<IpAddr>().expect("literal")]
        );
        assert_eq!(config.os_detection, OsDetection::Passive);
        assert_eq!(config.service_detection, ServiceDetection::Banner);
        assert_eq!(config.detection.ceiling(), Some(DetectionClass::Exploit));
        assert_eq!(config.retry.effort, ScanEffort::Single);
        assert_eq!(config.tcp_technique, TcpScanTechnique::Syn);

        let idle = config.idle_scan.expect("the request named a zombie");
        assert_eq!(idle.zombie, "192.0.2.9".parse::<IpAddr>().expect("literal"));
        assert_eq!(idle.zombie_port, Some(445));

        assert_eq!(config.evasion.source_port, Some(53));
        assert_eq!(config.evasion.ttl, Some(12));
        assert_eq!(config.evasion.decoys.len(), 1);

        let ports = request
            .ports()
            .expect("the request named ports")
            .expect("valid");
        assert!(ports.has_tcp(22) && ports.has_tcp(80));
    }

    /// The difference from a settings file, which warns about a key it does not
    /// know and applies the rest. A request is written by whoever is holding the
    /// error, so it is refused and the error names the field.
    #[test]
    fn a_misspelled_key_is_refused_rather_than_ignored() {
        let error = toml::from_str::<ScanRequest>("traceroot = true\n")
            .expect_err("a key nobody knows is not a request");

        let message = error.to_string();
        assert!(
            message.contains("traceroot"),
            "the error should name the key that was written: {message}"
        );
        assert!(
            message.contains("traceroute"),
            "the error should name the keys that would have worked: {message}"
        );
    }

    /// A request is the layer after a settings file, so where the two speak
    /// about one key the request wins.
    #[test]
    fn a_request_overrides_the_settings_a_file_had_already_applied() {
        let mut config = ZondConfig::default();

        let from_disk: Settings =
            toml::from_str("effort = \"single\"\ntls_enumeration = false\n").expect("settings");
        from_disk.apply_to(&mut config);

        request("[settings]\neffort = \"thorough\"\n").apply_to(&mut config);

        assert_eq!(config.retry.effort, ScanEffort::Thorough);
        assert!(
            !config.tls_enumeration,
            "a key the request said nothing about keeps what the file set"
        );
    }

    /// The engine refuses a profile like this when a scan starts. Refusing it
    /// where it was written names the key rather than the run.
    #[test]
    fn an_evasion_table_the_engine_would_refuse_is_refused_as_it_is_read() {
        let error = toml::from_str::<ScanRequest>("[evasion]\nfragment = 4\n")
            .expect_err("an unfragmentable MTU is not a profile");

        assert!(
            error.to_string().contains("fragment"),
            "the error should say which value was wrong: {error}"
        );
    }

    #[test]
    fn ports_fall_back_to_the_settings_table_when_the_request_names_none() {
        let request = request("[settings]\ndefault_ports = \"443\"\n");
        let ports = request
            .ports()
            .expect("the settings named ports")
            .expect("valid");

        assert!(ports.has_tcp(443));
        assert_eq!(ports.len(), 1);
    }

    #[test]
    fn a_port_specification_that_is_not_one_names_what_was_written() {
        let request = request("ports = \"nope\"\n");
        let error = request
            .ports()
            .expect("the request named ports")
            .expect_err("'nope' is not a port specification");

        assert!(matches!(&error, RequestError::Ports { spec, .. } if spec == "nope"));
    }

    #[tokio::test]
    async fn resolving_adds_exclusions_to_what_the_configuration_already_forbids() {
        let mut already = IpSet::new();
        already.insert_range("172.16.0.0/16".parse().expect("a valid range"));

        let mut config = ZondConfig {
            exclusions: Exclusions::new(already),
            ..Default::default()
        };

        let resolved = request("targets = [\"192.0.2.0/24\"]\nexclude = [\"192.0.2.7\"]\n")
            .resolve(None)
            .await
            .expect("literal addresses resolve without a resolver");

        resolved.apply_to(&mut config);

        for excluded in ["172.16.0.1", "192.0.2.7"] {
            assert!(
                config
                    .exclusions
                    .excludes(&excluded.parse().expect("literal")),
                "{excluded} was excluded by one of the two and must still be"
            );
        }
        assert!(
            !config
                .exclusions
                .excludes(&"192.0.2.8".parse().expect("literal"))
        );
        assert_eq!(resolved.ips().len(), 256);
    }

    #[tokio::test]
    async fn a_request_naming_no_targets_is_refused_rather_than_resolving_to_nothing() {
        let error = ScanRequest::new()
            .resolve(None)
            .await
            .expect_err("a request with no targets cannot be resolved");

        assert!(matches!(error, RequestError::NoTargets));
    }
}
