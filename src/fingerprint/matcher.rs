// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Signatures
//!
//! One [`Signature`] is a single service pattern plus the metadata to turn a
//! match into [`Evidence`]. The port index and the prefilter both address
//! signatures by index into one flat set.
//!
//! A signature's regex is compiled **lazily, once, on first match**, behind a
//! `OnceLock`. [`pattern::compile`] picks the engine (linear `regex`, or bounded
//! `fancy-regex` backtracking for backrefs and look-arounds). `build.rs`
//! validates the set with the same logic and size limit, so compilation does not
//! fail in a correctly built binary; if it does, the failure is logged.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::fingerprint::os::OsMetadata;
use crate::fingerprint::signature::{MAX_COMPILED_REGEX_BYTES, MatchRule};
use crate::model::host::OsSource;
use crate::model::port::build::normalised_release;
use crate::model::port::{Build, Distributor, Release, ReleaseBasis};
use crate::warn;

use super::model::{Evidence, SourceId};
use super::pattern::{self, CompiledPattern};
use crate::model::confidence::Confidence;

/// A single service signature: metadata, its pattern, and its lazily-compiled
/// regex.
#[derive(Debug)]
pub struct Signature {
    service: String,
    /// Whether a match names the service, or asserts nothing about it.
    ///
    /// Recog marks the second with `service.certainty = 0`: a rule that matches a
    /// token but identifies no software, such as a `version.bind` answer of
    /// `null`. Such a match must not put its parent `[service]` name on the port,
    /// or a `Server: null` header reads as DNS.
    identifies_service: bool,
    product: Option<String>,
    vendor: Option<String>,
    /// 1-based capture group holding the version string, if any.
    version_group: Option<u8>,
    pattern: String,
    /// `None` until first use; `Some(None)` if the pattern failed to compile.
    compiled: OnceLock<Option<CompiledPattern>>,

    /// What this rule says about the operating system underneath the service,
    /// where it says anything.
    ///
    /// Boxed: 2290 of the 4732 shipped rules name no operating system, and a scan
    /// holds every signature at once.
    os: Option<Box<OsMetadata>>,

    /// The `hw.*` keys, unresolved, for the hardware a rule describes.
    ///
    /// Boxed and absent on most signatures. Kept as the raw map because the
    /// values are templates a match fills from its own captures.
    // The box is eight bytes where the map would be forty-eight, per signature,
    // and most signatures have none.
    #[allow(clippy::box_collection)]
    hardware: Option<Box<HashMap<String, String>>>,

    /// The service's CPE, as the corpus writes it: either a literal, or a
    /// template naming `{service.version}`, the one variable any of the 1226
    /// `service.cpe23` rules uses, resolved against the matched version when
    /// the signature fires. Absent on a rule that names no platform identifier.
    cpe: Option<String>,

    /// A version the signature states outright, filling `{service.version}` for
    /// a rule whose pattern captures none, an IIS 5.0 banner that says `5.0` in
    /// prose the regex does not group.
    service_version: Option<String>,

    /// What runs the service, where the rule names it. See [`Component`].
    component: Option<Component>,

    /// Everything else the rule wants said about the service, as a template
    /// resolved against what the pattern captured.
    ///
    /// The general form of what [`Component`] states in two named halves, for a
    /// rule whose supplementary detail is not a runtime: an OpenSSH banner's
    /// `Debian-7+deb13u4` is the distribution's build of the service itself.
    /// Takes precedence over the component phrase where a rule states both.
    extrainfo: Option<String>,

    /// Whose build of the service the rule says it matched. See
    /// [`BuildTemplate`].
    build: Option<BuildTemplate>,
}

/// The runtime a service runs on, as its rule names it.
///
/// `Python` under a `SimpleHTTP` server, `.NET CLR` under `.NET Remoting`, `PHP`
/// under an Apache. Recog calls it `service.component.*` and 347 rules in the
/// imported corpus carry one. A report prints it in parentheses after the
/// product.
///
/// The runtime is often the exploitable part: `SimpleHTTP/0.6 Python/3.13.5`
/// names a trivial server and a runtime with a CVE history.
#[derive(Debug)]
struct Component {
    /// What it is, possibly a `{capture:N}` template.
    product: Option<String>,
    /// Which version of it, likewise.
    version: Option<String>,
}

impl Component {
    /// The component a rule names, or [`None`] where it names none.
    fn from_map(rule: &MatchRule) -> Option<Self> {
        let product = metadata_value(rule, "service.component.product");
        let version = metadata_value(rule, "service.component.version");

        (product.is_some() || version.is_some()).then_some(Self { product, version })
    }

    /// The component as the one phrase a report shows, templates resolved
    /// against what the pattern captured.
    ///
    /// Either half alone is still reported.
    fn resolve(&self, captures: &[String]) -> Option<String> {
        let product = super::os::fill(self.product.as_deref(), captures);
        let version = super::os::fill(self.version.as_deref(), captures);

        match (product, version) {
            (Some(product), Some(version)) => Some(format!("{product} {version}")),
            (Some(only), None) | (None, Some(only)) => Some(only),
            (None, None) => None,
        }
    }
}

/// Whose build of the software a rule says it matched, as the rule writes it.
///
/// Three keys, each a literal or a `{capture:N}` template:
/// `service.build.distributor` (required for the rest to mean anything),
/// `service.build.revision` and `service.build.release`. A distributor that
/// [`Distributor::from_name`] does not know yields no build, so a rule
/// capturing the word before a hyphen in an OpenSSH comment reads
/// `Ubuntu-2ubuntu2.13` as a build and `hpn-13v11`, a patch set, as nothing.
#[derive(Debug)]
struct BuildTemplate {
    distributor: String,
    revision: Option<String>,
    release: Option<String>,
}

impl BuildTemplate {
    /// The template a rule states, or [`None`] where it names no distributor.
    fn from_map(rule: &MatchRule) -> Option<Self> {
        Some(Self {
            distributor: metadata_value(rule, "service.build.distributor")?,
            revision: metadata_value(rule, "service.build.revision"),
            release: metadata_value(rule, "service.build.release"),
        })
    }

    /// The build, templates resolved against what the pattern captured, each
    /// part bounded like every field lifted off a reply.
    fn resolve(&self, captures: &[String]) -> Option<Build> {
        let distributor = super::os::fill(Some(&self.distributor), captures)?;
        let distributor = Distributor::from_name(&distributor)?;
        let mut build = Build::new(distributor);
        if let Some(release) = super::os::fill(self.release.as_deref(), captures)
            .as_deref()
            .and_then(super::identity_field)
            .and_then(|release| normalised_release(distributor, release))
        {
            build = build.with_release(Release::new(release, ReleaseBasis::Banner));
        }
        if let Some(revision) = super::os::fill(self.revision.as_deref(), captures)
            .as_deref()
            .and_then(super::identity_field)
        {
            build = build.with_revision(revision.to_owned());
        }
        Some(build)
    }
}

/// Whether a rule identifies the service it belongs to.
///
/// True unless the rule sets `service.certainty = 0`, Recog's mark for a match
/// that names no software, such as a bare `null`.
fn identifies_service(rule: &MatchRule) -> bool {
    metadata_value(rule, "service.certainty")
        .map(|certainty| !matches!(certainty.trim(), "0" | "0.0"))
        .unwrap_or(true)
}

/// A non-empty metadata value for `key`, or [`None`].
fn metadata_value(rule: &MatchRule, key: &str) -> Option<String> {
    rule.metadata
        .as_ref()?
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
}

/// Resolves a `service.cpe23` template against `version`.
///
/// The corpus uses one variable, `{service.version}`; a literal CPE is returned
/// unchanged. With no version to fill, the template resolves to [`None`], since
/// a consumer would mis-match a CPE with an empty version (`cpe:/a:perl:perl:`).
fn resolve_service_cpe(template: &str, version: Option<&str>) -> Option<String> {
    const VERSION: &str = "{service.version}";
    if !template.contains(VERSION) {
        return Some(template.to_string());
    }
    Some(template.replace(VERSION, version?))
}

impl Signature {
    /// Builds a signature from a rule owned by `service`. Stores metadata only:
    /// no regex is compiled until [`Signature::identify`] is first called.
    pub fn new(service: &str, rule: &MatchRule) -> Self {
        Self {
            service: service.to_string(),
            identifies_service: identifies_service(rule),
            product: rule.product.clone(),
            vendor: rule.vendor.clone(),
            version_group: rule.version_group,
            pattern: rule.pattern.clone(),
            compiled: OnceLock::new(),
            hardware: rule.metadata.as_ref().and_then(|metadata| {
                metadata
                    .keys()
                    .any(|key| key.starts_with("hw."))
                    .then(|| Box::new(metadata.clone()))
            }),
            os: rule
                .metadata
                .as_ref()
                .and_then(OsMetadata::from_map)
                .map(Box::new),
            cpe: metadata_value(rule, "service.cpe23"),
            service_version: metadata_value(rule, "service.version"),
            component: Component::from_map(rule),
            extrainfo: metadata_value(rule, "service.extrainfo"),
            build: BuildTemplate::from_map(rule),
        }
    }

    /// The raw pattern, for build-time literal extraction by the prefilter.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Compiles the regex on first call and caches it. Returns `None` if neither
    /// engine can compile the pattern (logged once).
    pub fn compile(&self) {
        self.compiled();
    }

    /// Whether the regex has been compiled.
    #[cfg(test)]
    pub(crate) fn is_compiled(&self) -> bool {
        self.compiled.get().is_some()
    }

    fn compiled(&self) -> Option<&CompiledPattern> {
        self.compiled
            .get_or_init(
                || match pattern::compile(&self.pattern, MAX_COMPILED_REGEX_BYTES) {
                    Ok(compiled) => Some(compiled),
                    Err(e) => {
                        warn!(
                            "fingerprint signature for service '{}' was skipped: its pattern \
                             failed to compile ({e}); pattern = {:?}",
                            self.service, self.pattern
                        );
                        None
                    }
                },
            )
            .as_ref()
    }

    /// Matches `response`, returning the [`Evidence`] it yields paired with a
    /// [`MatchQuality`] for ranking it against other signatures that match the
    /// same response. `None` if the pattern does not match.
    ///
    /// `attested_by` says what kind of text this is (a daemon's banner, a
    /// management agent's description of its machine) and decides what a match
    /// is worth as evidence *about the host*. The service reading is unaffected.
    pub fn identify(&self, response: &str, attested_by: OsSource) -> Option<Match> {
        // Captures are collected only where templates need them; this runs for
        // every candidate on every banner.
        let wants_captures = self.os.is_some()
            || self.component.is_some()
            || self.extrainfo.is_some()
            || self.build.is_some();
        let matched = self.compiled()?.identify_with_captures(
            response,
            self.version_group,
            wants_captures,
        )?;
        // Bounded by `MAX_IDENTITY_BYTES` and trimmed, since a group running to
        // the end of a line takes the CR and one stopping at a parenthesis takes
        // the space before it.
        let version = matched
            .version
            .as_deref()
            .and_then(super::identity_field)
            .map(str::to_owned);

        let confidence = if version.is_some() {
            Confidence::Strong
        } else {
            Confidence::Probable
        };

        let detail = self.product.is_some() as u8 + self.vendor.is_some() as u8;

        let cpe = self.cpe.as_deref().and_then(|template| {
            resolve_service_cpe(
                template,
                version.as_deref().or(self.service_version.as_deref()),
            )
        });

        let mut evidence = Evidence::new(SourceId::BannerRegex, confidence);
        if self.identifies_service {
            evidence = evidence.with_service(self.service.clone());
        }
        evidence.product = self.product.clone();
        evidence.vendor = self.vendor.clone();
        evidence.version = version;
        evidence.cpe = cpe;
        let captures = matched.captures.as_deref().unwrap_or(&[]);
        // Bounded like the version: both resolve a template against a capture
        // from a remote response. See `MAX_IDENTITY_BYTES`.
        evidence.extrainfo = super::os::fill(self.extrainfo.as_deref(), captures)
            .or_else(|| {
                self.component
                    .as_ref()
                    .and_then(|component| component.resolve(captures))
            })
            .filter(|extra| super::identity_field(extra).is_some());
        evidence.build = self
            .build
            .as_ref()
            .and_then(|build| build.resolve(captures));

        Some(Match {
            evidence,
            quality: MatchQuality {
                confidence,
                detail,
                specificity: matched.match_len,
            },
            hardware: self.hardware.as_deref().and_then(|metadata| {
                super::os::hardware_from(metadata, matched.captures.as_deref().unwrap_or(&[]))
            }),
            arch: self.os.as_deref().and_then(|metadata| {
                metadata
                    .resolve(matched.captures.as_deref().unwrap_or(&[]))
                    .arch
            }),
            os: self.os.as_deref().and_then(|metadata| {
                super::os::banner_evidence(
                    metadata,
                    matched.captures.as_deref().unwrap_or(&[]),
                    attested_by,
                )
            }),
        })
    }
}

/// The service name to report for `winner`, given every match `all` made against
/// one response.
///
/// Usually the winner's own. The exception is a winner naming the generic `http`
/// baseline with an application as its product: a Grafana page wins as `http`
/// with product `Grafana`, while a signature naming the service `grafana` loses
/// on detail. Both say the same thing, so the port is called `grafana`.
///
/// The specific service must name the same application: its name and the
/// winner's product must contain one another. This keeps a stray `dns` off a
/// `Server: null`.
pub fn resolved_service_name(winner: &Match, all: &[Match]) -> Option<String> {
    if !is_generic_service(winner.evidence.service.as_deref()) {
        return winner.evidence.service.clone();
    }
    let Some(product) = winner.evidence.product.as_deref() else {
        return winner.evidence.service.clone();
    };

    all.iter()
        .find(|m| {
            m.quality.confidence == winner.quality.confidence
                && !is_generic_service(m.evidence.service.as_deref())
                && m.evidence
                    .service
                    .as_deref()
                    .is_some_and(|service| names_the_same(service, product))
        })
        .and_then(|m| m.evidence.service.clone())
        .or_else(|| winner.evidence.service.clone())
}

/// Whether a service name is a generic protocol baseline. `http` is the one that
/// matters: the HTTP analyzer and the corpus's `generic_http` rule mint it for
/// any web response.
fn is_generic_service(service: Option<&str>) -> bool {
    matches!(service, Some("http"))
}

/// Whether a service name and a product name the same software, case-insensitive:
/// one contains the other, so `grafana` matches `Grafana` and `Grafana v8` alike.
fn names_the_same(service: &str, product: &str) -> bool {
    let service = service.to_ascii_lowercase();
    let product = product.to_ascii_lowercase();
    product.contains(&service) || service.contains(&product)
}

/// One signature's reading of one response.
///
/// A rule answers up to four questions: what service this is
/// ([`evidence`](Self::evidence)), what box it runs on
/// ([`hardware`](Self::hardware)), what system runs on that box
/// ([`os`](Self::os)), and what silicon underneath ([`arch`](Self::arch)).
/// [`quality`](Self::quality) ranks it against other rules that fired.
pub struct Match {
    /// What this match says the service is: product, vendor, version, CPE, with
    /// every template already resolved against the capture groups.
    pub evidence: Evidence,
    /// How firmly this match holds, for ranking against other rules that fired
    /// on the same response.
    pub quality: MatchQuality,
    /// The hardware this match describes, templates already resolved.
    ///
    /// Separate from [`os`](Self::os): a NETGEAR ReadyNAS runs Linux, and the box
    /// and its system are two facts. 536 shipped rules name only the box.
    pub hardware: Option<crate::model::host::HardwareInfo>,
    /// The instruction set this match named, whether or not it named anything
    /// else.
    ///
    /// Separate from [`os`](Self::os) because seven rules state an architecture
    /// and nothing more (`x64|amd64|x86_64` against a `uname` banner).
    /// [`evidence_from`](super::os::banner_evidence) declines those, since a
    /// nameless candidate cannot vote. The architecture is collected like
    /// [`hardware`](Self::hardware) and filled into whichever reading wins.
    pub arch: Option<String>,
    /// What this match says about the operating system underneath the service,
    /// with its templates already resolved against the capture groups.
    ///
    /// Kept off [`Evidence`]: a banner identifies a *service*, and what it implies
    /// about the host is a weaker, second inference resolved by other rules.
    pub os: Option<crate::model::host::OsEvidence>,
}

/// How specific a signature's match is, for ranking competing matches against
/// one response. Ordered least-to-most specific.
///
/// `confidence` is compared first, so a captured version (`Strong`) outranks
/// any versionless match. Within one level, `detail`, the number of identity
/// fields the signature supplies (product, vendor), breaks the tie, so
/// `Server: Apache` outranks a bare `HTTP/1.1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MatchQuality {
    confidence: Confidence,
    detail: u8,
    specificity: usize,
}

impl MatchQuality {
    /// How much of the response the pattern accounted for.
    ///
    /// Lets a caller collecting a field from several matches prefer the longest
    /// read: `x86_64` and the `x86` rule inside it both fire on one banner.
    pub fn specificity(self) -> usize {
        self.specificity
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

    fn rule(pattern: &str, version_group: Option<u8>, product: Option<&str>) -> MatchRule {
        MatchRule {
            name: None,
            pattern: pattern.to_string(),
            version_group,
            vendor: None,
            product: product.map(str::to_string),
            context: None,
            example: None,
            metadata: None,
        }
    }

    fn rule_with_metadata(
        pattern: &str,
        version_group: Option<u8>,
        metadata: &[(&str, &str)],
    ) -> MatchRule {
        let mut rule = rule(pattern, version_group, None);
        rule.metadata = Some(
            metadata
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
        );
        rule
    }

    /// The runtime under the server is carried. A rule may also state extrainfo
    /// as a template over its captures.
    #[test]
    fn a_rule_can_state_extrainfo_over_its_own_captures() {
        let mut rule = rule(r"^OpenSSH_(\S+) (\S+)", Some(1), Some("OpenSSH"));
        rule.metadata = Some(
            [("service.extrainfo".to_string(), "{capture:2}".to_string())]
                .into_iter()
                .collect(),
        );

        let matched = Signature::new("ssh", &rule)
            .identify("OpenSSH_10.0p2 Debian-7+deb13u4", OsSource::ServiceBanner)
            .expect("the pattern matches");
        assert_eq!(
            matched.evidence.extrainfo.as_deref(),
            Some("Debian-7+deb13u4")
        );
    }

    /// Extrainfo is bounded like the version.
    #[test]
    fn stated_extrainfo_past_the_bound_is_refused() {
        let mut rule = rule(r"^OpenSSH_(\S+) (\S+)", Some(1), Some("OpenSSH"));
        rule.metadata = Some(
            [("service.extrainfo".to_string(), "{capture:2}".to_string())]
                .into_iter()
                .collect(),
        );

        let hostile = format!(
            "OpenSSH_10.0p2 {}",
            "A".repeat(crate::fingerprint::MAX_IDENTITY_BYTES + 1)
        );
        let matched = Signature::new("ssh", &rule)
            .identify(&hostile, OsSource::ServiceBanner)
            .expect("the pattern still matches");
        assert_eq!(matched.evidence.extrainfo, None);
    }

    #[test]
    fn the_component_a_rule_names_becomes_the_services_extra_info() {
        let ev = Signature::new(
            "http",
            &rule_with_metadata(
                r"(?i)^SimpleHTTP/((?:\d+\.)*\d+)\s*Python/((?:\d+\.)*\d+)$",
                Some(1),
                &[
                    ("service.component.product", "Python"),
                    ("service.component.version", "{capture:2}"),
                ],
            ),
        )
        .identify("SimpleHTTP/0.6 Python/3.13.5", OsSource::ServiceBanner)
        .expect("matches")
        .evidence;

        assert_eq!(ev.version.as_deref(), Some("0.6"));
        assert_eq!(ev.extrainfo.as_deref(), Some("Python 3.13.5"));
    }

    #[test]
    fn a_service_cpe_is_resolved_carried_and_dropped_when_unfillable() {
        // A template resolves against the captured version.
        let ev = Signature::new(
            "http",
            &rule_with_metadata(
                r"^libwww-perl-daemon/([.0-9]+)$",
                Some(1),
                &[("service.cpe23", "cpe:/a:perl:perl:{service.version}")],
            ),
        )
        .identify("libwww-perl-daemon/1.36", OsSource::ServiceBanner)
        .expect("matches")
        .evidence;
        assert_eq!(ev.cpe.as_deref(), Some("cpe:/a:perl:perl:1.36"));

        // A literal CPE is carried verbatim.
        let ev = Signature::new(
            "http",
            &rule_with_metadata(
                "^Transmission$",
                None,
                &[("service.cpe23", "cpe:/a:transmissionbt:transmission:-")],
            ),
        )
        .identify("Transmission", OsSource::ServiceBanner)
        .unwrap()
        .evidence;
        assert_eq!(
            ev.cpe.as_deref(),
            Some("cpe:/a:transmissionbt:transmission:-")
        );

        // A template with no version to fill is dropped.
        let ev = Signature::new(
            "http",
            &rule_with_metadata(
                "^perl$",
                None,
                &[("service.cpe23", "cpe:/a:perl:perl:{service.version}")],
            ),
        )
        .identify("perl", OsSource::ServiceBanner)
        .unwrap()
        .evidence;
        assert_eq!(ev.cpe, None);

        // An explicit `service.version` fills the template where the pattern
        // captures none.
        let ev = Signature::new(
            "ftp",
            &rule_with_metadata(
                "^220 Microsoft FTP",
                None,
                &[
                    ("service.cpe23", "cpe:/a:microsoft:iis:{service.version}"),
                    ("service.version", "5.0"),
                ],
            ),
        )
        .identify("220 Microsoft FTP Service", OsSource::ServiceBanner)
        .unwrap()
        .evidence;
        assert_eq!(ev.cpe.as_deref(), Some("cpe:/a:microsoft:iis:5.0"));
    }

    #[test]
    fn captures_version_and_reports_strong_confidence() {
        let sig = Signature::new(
            "ssh",
            &rule(r"^SSH-[\d.]+-OpenSSH_([\w.]+)", Some(1), Some("OpenSSH")),
        );
        let ev = sig
            .identify("SSH-2.0-OpenSSH_9.6p1 Debian", OsSource::ServiceBanner)
            .expect("should match")
            .evidence;
        assert_eq!(ev.service.as_deref(), Some("ssh"));
        assert_eq!(ev.product.as_deref(), Some("OpenSSH"));
        assert_eq!(ev.version.as_deref(), Some("9.6p1"));
        assert_eq!(ev.confidence, Confidence::Strong);
    }

    /// A rule that recognised the protocol and nothing else names no product.
    ///
    /// The service name is the protocol; the product is the software. Copying one
    /// into the other would report `dns` as the software behind DNS.
    #[test]
    fn bare_match_is_probable_and_names_no_product() {
        let sig = Signature::new("http", &rule("^HTTP/1.1", None, None));
        let ev = sig
            .identify("HTTP/1.1 200 OK", OsSource::ServiceBanner)
            .expect("should match")
            .evidence;

        assert_eq!(ev.confidence, Confidence::Probable);
        assert_eq!(ev.service.as_deref(), Some("http"));
        assert_eq!(
            ev.product, None,
            "the rule named no product, so neither does the evidence"
        );
    }

    #[test]
    fn specific_match_outranks_generic_for_same_response() {
        let response = "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n";
        // Generic protocol match: no version, no explicit product/vendor.
        let generic = Signature::new("http", &rule(r"(?i)^HTTP/\d+\.\d+\s+\d+", None, None));
        // Specific server match: captures a version and names product + vendor.
        let mut nginx_rule = rule(r"(?i)Server:\s*nginx/([\d.]+)", Some(1), Some("nginx"));
        nginx_rule.vendor = Some("NGINX".to_string());
        let nginx = Signature::new("http", &nginx_rule);

        let generic_q = generic
            .identify(response, OsSource::ServiceBanner)
            .expect("generic matches")
            .quality;
        let nginx_q = nginx
            .identify(response, OsSource::ServiceBanner)
            .expect("nginx matches")
            .quality;
        assert!(nginx_q > generic_q, "specific match must outrank generic");
    }

    #[test]
    fn no_match_returns_none() {
        let sig = Signature::new("http", &rule("^HTTP/1.1", None, None));
        assert!(
            sig.identify("SSH-2.0-OpenSSH_9.6", OsSource::ServiceBanner)
                .is_none()
        );
    }

    #[test]
    fn backreference_signature_matches_via_the_fancy_engine() {
        // A backreference needs the backtracking engine.
        let sig = Signature::new("dup", &rule(r"^(\w+) \1$", None, None));
        assert!(
            sig.identify("token token", OsSource::ServiceBanner)
                .is_some()
        );
        assert!(
            sig.identify("token other", OsSource::ServiceBanner)
                .is_none()
        );
    }

    #[test]
    fn unsupported_pattern_is_skipped_not_fatal() {
        // A syntax error neither engine compiles yields nothing.
        let sig = Signature::new("x", &rule("(", None, None));
        assert!(sig.identify("aa", OsSource::ServiceBanner).is_none());
    }
}
