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
//! match into [`Evidence`]. Signatures are the flat, globally-indexed unit the
//! rest of the engine works in: the port index and the prefilter both address
//! them by index, so a candidate set from either can be matched uniformly.
//!
//! A signature's regex is compiled **lazily, once, on first match**, guarded by
//! a `OnceLock`, never eagerly for the whole set, never per connection. Which
//! engine compiles it (the linear `regex` engine, or the bounded `fancy-regex`
//! backtracking engine for backref/lookaround patterns) is decided by
//! [`pattern::compile`](super::pattern::compile); see that module for the
//! selection and safety rules. The signature set is validated at build time
//! (see `build.rs`) with the same logic and size limit, so in a correctly built
//! binary compilation never fails; the `None` branch is defence in depth and is
//! logged, not silently dropped.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::fingerprint::os::OsMetadata;
use crate::fingerprint::signature::{MAX_COMPILED_REGEX_BYTES, MatchRule};
use crate::model::host::OsSource;
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
    /// token but identifies no software, a `version.bind` answer of `null`, a
    /// bare string that only rules out other readings. Such a match must not put
    /// its parent `[service]` name on the port, or a `Server: null` header reads
    /// as DNS. False for those rules, true for the rest.
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
    /// Boxed, and absent on most signatures: 2290 of the 4732 shipped rules name
    /// no operating system, and a scan holds every signature at once. Kept at all
    /// because dropping it is what made a full imported OS corpus invisible to
    /// the engine that compiled it.
    os: Option<Box<OsMetadata>>,

    /// The `hw.*` keys, unresolved, for the hardware a rule describes.
    ///
    /// Boxed and absent on most signatures, as the operating system's are: a
    /// scan holds every signature at once. Kept as the raw map because the
    /// values are templates a match fills from its own captures.
    // `box_collection` reads the indirection as waste, which is the opposite of
    // what it buys here: absent on most of the corpus, the box is eight bytes
    // where the map would be forty-eight, held once per signature.
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
}

/// The runtime a service runs on, as its rule names it.
///
/// `Python` under a `SimpleHTTP` server, `.NET CLR` under `.NET Remoting`, `PHP`
/// under an Apache. Recog calls it `service.component.*` and 347 rules in the
/// imported corpus carry one, which is the field a report prints in parentheses
/// after the product.
///
/// Worth carrying because the runtime is often the exploitable half. A banner
/// reading `SimpleHTTP/0.6 Python/3.13.5` names a server nobody attacks and a
/// runtime with a CVE history, and a scanner that read the second and kept only
/// the first has thrown away the part somebody scanned for.
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
    /// Either half alone is still worth saying: a rule that names the runtime
    /// and captures no version has established which runtime, and one that
    /// captures a version under a product the reader can see has established
    /// which version.
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

/// Whether a rule identifies the service it belongs to.
///
/// True unless the rule sets `service.certainty = 0`, Recog's mark for a match
/// that names no software: it fired, but what it establishes about the service is
/// nothing. Honouring it is what stops an "assert nothing" token like a bare
/// `null` from tagging whatever carried it with the rule's parent service.
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
/// The corpus uses exactly one variable, `{service.version}`; a literal CPE is
/// returned unchanged. A template whose variable has no version to fill
/// resolves to [`None`], because a CPE ending in an empty version,
/// `cpe:/a:perl:perl:`, is worse than none: a consumer tries to match on it and
/// matches the wrong thing.
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
    /// `attested_by` says what kind of text this is, a daemon's banner, a
    /// management agent's own description of its machine, and decides what a
    /// match is worth as evidence *about the host*. It does not touch the
    /// service reading, which is the same match either way.
    pub fn identify(&self, response: &str, attested_by: OsSource) -> Option<Match> {
        // Capture groups are collected only for a signature whose operating-system
        // metadata has templates to fill from them. Most have neither, and this
        // runs against every candidate signature for every banner.
        let wants_captures =
            self.os.is_some() || self.component.is_some() || self.extrainfo.is_some();
        let matched = self.compiled()?.identify_with_captures(
            response,
            self.version_group,
            wants_captures,
        )?;
        // A capture past the bound is a pattern that ran away over a hostile
        // response, not a version. See `MAX_IDENTITY_BYTES`.
        let version = matched
            .version
            .filter(|version| super::identity_field(version).is_some());

        // A captured version is a materially stronger signal than a bare match.
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
        // Bounded like the version above it: both routes here resolve a corpus
        // template against a capture taken from a remote response, so a pattern
        // that ran away puts a kilobyte in a report field. See
        // `MAX_IDENTITY_BYTES`.
        evidence.extrainfo = super::os::fill(self.extrainfo.as_deref(), captures)
            .or_else(|| {
                self.component
                    .as_ref()
                    .and_then(|component| component.resolve(captures))
            })
            .filter(|extra| super::identity_field(extra).is_some());

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

/// A signature's successful match against a response: the [`Evidence`] it
/// yields, paired with the [`MatchQuality`] used to choose the most specific
/// match when several signatures match the same response.
/// The service name to report for `winner`, given every match `all` made against
/// one response.
///
/// Usually the winner's own. The exception is the winner that names the generic
/// `http` baseline while capturing an application as its product: the corpus's
/// `generic_http` rule and the HTTP analyzer both mint `http` for any web
/// response, so a page a title says is Grafana wins the ranking as `http` with
/// `Grafana` in the product, and a signature that named the service `grafana`
/// outright loses on detail. The two are the same identification, one by name and
/// one by product, so the specific name is preferred and the port is called
/// `grafana` rather than `http`.
///
/// The specific service must name the same application: its name and the winner's
/// product have to contain one another, so `grafana` is taken for a `Grafana`
/// product but a rule that coincidentally matched some unrelated text is not,
/// which is what keeps a stray `dns` off a `Server: null`.
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

/// Whether a service name is a generic protocol baseline rather than an
/// identification of the software. `http` is the one that matters: it is what the
/// HTTP analyzer and the corpus's `generic_http` rule mint for any web response.
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

pub struct Match {
    pub evidence: Evidence,
    pub quality: MatchQuality,
    /// The hardware this match describes, templates already resolved.
    ///
    /// Apart from [`os`](Self::os) for the reason that field gives about
    /// [`Evidence`], one question further out: a NETGEAR ReadyNAS runs Linux, and
    /// the box and the system on it are two facts rather than one. Five hundred
    /// and thirty-six shipped rules name only the box.
    pub hardware: Option<crate::model::host::HardwareInfo>,
    /// What this match says about the operating system underneath the service,
    /// with its templates already resolved against the capture groups.
    ///
    /// A separate field rather than more fields on [`Evidence`] because it
    /// answers a different question and is resolved by a different set of rules.
    /// A banner identifies a *service*; that it also implies a host is a second
    /// inference, weaker than the first, and one a caller uninterested in
    /// operating systems should be able to ignore entirely.
    pub os: Option<crate::model::host::OsEvidence>,
}

/// How specific a signature's match is, for ranking competing matches against
/// one response. Ordered least-to-most specific.
///
/// `confidence` is compared first: a captured version (`Strong`) is the
/// strongest identity signal, so it outranks any versionless match regardless
/// of other fields. Within one confidence level, `detail`, the number of
/// identity fields the signature supplies (an explicit product, a vendor),
/// breaks the tie, so a specific `Server: Apache` match outranks a bare
/// `HTTP/1.1` protocol match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MatchQuality {
    confidence: Confidence,
    detail: u8,
    specificity: usize,
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

    /// The runtime under the server is the half worth scanning for: a
    /// `SimpleHTTP` listener is nobody's target and the interpreter behind it
    /// has a CVE history. The corpus captured it and nothing carried it.
    #[test]
    /// A rule may state extrainfo outright, as a template over its captures,
    /// for supplementary detail that is not a runtime.
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

    /// And what it states is held to the same bound the version is, since both
    /// resolve against a capture from a response the scan did not write.
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
        // A template resolves against the captured version, the wiring that was
        // dropping 1226 corpus CPEs before Evidence.cpe was ever set.
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

        // A template with no version to fill is dropped, never emitted with an
        // empty version a consumer would mis-match on.
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
    /// The service name is what protocol was spoken; the product is what
    /// software spoke it. Copying the first into the second reports `dns` as
    /// the software behind DNS, which is a claim nothing made, and one that
    /// then disagrees with every other scanner's answer for the same port.
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
        // A backreference: unsupported by the linear engine, so this signature
        // only identifies at all because of the backtracking fallback. It used
        // to be rejected outright at build time.
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
        // A genuine syntax error that neither engine can compile: identification
        // yields nothing rather than panicking.
        let sig = Signature::new("x", &rule("(", None, None));
        assert!(sig.identify("aa", OsSource::ServiceBanner).is_none());
    }
}
