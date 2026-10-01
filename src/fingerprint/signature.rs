// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The service-signature authoring schema
//!
//! What an `assets/fingerprinting` TOML file is allowed to say, as types.
//!
//! `build.rs` loads this file with `#[path]`, so the build validates against the
//! same schema the runtime reads.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// What separates a corpus file from the rule inside it in a [`rule_id`].
///
/// `#` because ninety-three imported rules carry a colon in their name (`ISC
/// BIND: Ubuntu`). [`claim_rule_id`] refuses names containing it.
pub const RULE_ID_SEPARATOR: char = '#';

/// The root every corpus slug is written relative to.
pub const CORPUS_ROOT: &str = "assets/fingerprinting";

/// The stable name of one corpus file, as an identifier writes it: the path
/// under [`CORPUS_ROOT`] with the `.toml` dropped, separators normalised to `/`.
///
/// `assets/fingerprinting/remote/ssh.toml` becomes `remote/ssh`. `None` for a
/// path outside the corpus root.
pub fn corpus_slug(path: &Path) -> Option<String> {
    let root = Path::new(CORPUS_ROOT);
    let relative = path.strip_prefix(root).ok()?;
    let stem = relative.to_str()?.strip_suffix(".toml")?;
    Some(stem.replace(std::path::MAIN_SEPARATOR, "/"))
}

/// The identifier for one rule or probe: its file's [`corpus_slug`], then
/// [`RULE_ID_SEPARATOR`], then the name it was authored under.
///
/// Names are unique within a file, so this is unique across the corpus;
/// [`claim_rule_id`] checks it at build time.
///
/// It survives edits to the pattern, so a rule can be cited and followed across
/// releases. Moving the file changes it.
pub fn rule_id(slug: &str, name: &str) -> String {
    format!("{slug}{RULE_ID_SEPARATOR}{name}")
}

/// Why a rule could not be given an identifier.
///
/// Exhaustive: these are the only three ways a file can fail to name a rule
/// uniquely, and the build script matches on them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleIdDefect {
    /// The rule states no `name`, so there is nothing to identify it by.
    Unnamed,
    /// The name contains [`RULE_ID_SEPARATOR`], which would make the identifier
    /// ambiguous to split.
    SeparatorInName(String),
    /// Another rule or probe in the same file already claimed this name.
    Duplicate(String),
}

impl std::fmt::Display for RuleIdDefect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unnamed => write!(f, "states no name, so it cannot be identified or cited"),
            Self::SeparatorInName(name) => write!(
                f,
                "is named '{name}', which contains the '{RULE_ID_SEPARATOR}' that separates a \
                 file from the rule inside it"
            ),
            Self::Duplicate(name) => {
                write!(
                    f,
                    "is named '{name}', which another rule in this file claimed"
                )
            }
        }
    }
}

/// Claims `name` for a rule in the file `slug`, returning the identifier.
///
/// `seen` is the set of names already taken in that file; use a fresh set per
/// file. Probes and match rules share it, since they share the identifier space.
pub fn claim_rule_id(
    slug: &str,
    name: Option<&str>,
    seen: &mut std::collections::BTreeSet<String>,
) -> Result<String, RuleIdDefect> {
    let name = name
        .filter(|n| !n.is_empty())
        .ok_or(RuleIdDefect::Unnamed)?;
    if name.contains(RULE_ID_SEPARATOR) {
        return Err(RuleIdDefect::SeparatorInName(name.to_string()));
    }
    if !seen.insert(name.to_string()) {
        return Err(RuleIdDefect::Duplicate(name.to_string()));
    }
    Ok(rule_id(slug, name))
}

/// Upper bound on a single compiled signature's memory footprint.
///
/// The `regex` crate defaults to 10 MiB; a few signatures with large bounded
/// repetitions (e.g. `{1,512}`) compile just past it. Shared by the runtime
/// matcher and the build-time validator.
pub const MAX_COMPILED_REGEX_BYTES: usize = 32 * 1024 * 1024;

/// Upper bound on a single UDP probe payload.
///
/// A probe draws at most one reply, so a payload large enough to fragment costs
/// more than it can return. Shared by the build-time validator and the runtime
/// tests.
pub const MAX_UDP_PROBE_BYTES: usize = 512;

/// Decodes the backslash escapes in an authored probe payload into raw bytes.
///
/// Payloads are authored as TOML *literal* strings (e.g. `'GET /
/// HTTP/1.1\r\n\r\n'`), so escapes arrive verbatim. This resolves `\r`, `\n`,
/// `\t`, `\0`, `\xHH` and `\\` to the bytes they denote; any other escape is
/// kept literally.
///
/// Lives beside the schema so `build.rs` and the runtime decode payloads the
/// same way.
pub fn unescape(payload: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len());
    let mut chars = payload.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.extend_from_slice(c.encode_utf8(&mut [0u8; 4]).as_bytes());
            continue;
        }
        match chars.next() {
            Some('r') => out.push(b'\r'),
            Some('n') => out.push(b'\n'),
            Some('t') => out.push(b'\t'),
            Some('0') => out.push(0),
            Some('\\') => out.push(b'\\'),
            Some('x') => {
                let hi = chars.next().and_then(|h| h.to_digit(16));
                let lo = chars.next().and_then(|l| l.to_digit(16));
                match (hi, lo) {
                    (Some(hi), Some(lo)) => out.push((hi * 16 + lo) as u8),
                    // Malformed \xHH: keep the marker.
                    _ => out.extend_from_slice(b"\\x"),
                }
            }
            // Unknown escape (or trailing backslash): keep it literally.
            Some(other) => {
                out.push(b'\\');
                out.extend_from_slice(other.encode_utf8(&mut [0u8; 4]).as_bytes());
            }
            None => out.push(b'\\'),
        }
    }
    out
}

/// The `[service]` table: who a signature file is about, and where that service
/// is expected to be found.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSignature {
    /// The service's canonical name, the one a report prints and every rule and
    /// probe in the file registers under.
    pub name: String,
    /// The ports this service owns. Each indexes the file's rules and probes
    /// under that number in [`SignatureDb`](crate::fingerprint::SignatureDb), and
    /// labels the port with the service's name before anything is asked.
    ///
    /// A number several services share belongs in
    /// [`shared_ports`](Self::shared_ports).
    ///
    /// An empty list is valid: the file's rules are reached by global matching.
    pub default_ports: Vec<u16>,
    /// Ports this service is probed and matched on without being named by them.
    ///
    /// Indexed like [`default_ports`](Self::default_ports) for rules and probes,
    /// but absent from the port-to-name index, so the port is not labelled
    /// before asking.
    ///
    /// On a contested number, every claimant but its owner declares it here:
    /// 8080 is `http`'s to name and Squid's to match.
    #[serde(default)]
    pub shared_ports: Vec<u16>,
    /// A line of prose naming the service, for whoever reads the corpus.
    pub description: Option<String>,
    /// Where the definition came from, when it was not authored here. The
    /// files under `assets/fingerprinting/imported` set it (`"Rapid7 Recog"`)
    /// and name the upstream licence they arrived under in their own header.
    pub attribution: Option<String>,

    /// The application protocol this service is carried over, where it is
    /// carried over one somebody else can also speak. `http` for Grafana,
    /// absent for Redis.
    ///
    /// The corpus gives a product its own service name (`grafana`), so a
    /// detection about HTTP names the protocol through
    /// [`Rule::speaks`](crate::detect::manifest::Rule::speaks) instead of every
    /// product.
    ///
    /// It describes what this signature matched on. Riak, Neo4j and RethinkDB
    /// have HTTP APIs but are fingerprinted by their binary protocols, so none
    /// sets it.
    #[serde(default)]
    pub speaks: Option<String>,
}

impl ServiceSignature {
    /// A service named `name`, registered on no port until some are pushed
    /// onto [`default_ports`](Self::default_ports).
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            default_ports: Vec::new(),
            shared_ports: Vec::new(),
            description: None,
            attribution: None,
            speaks: None,
        }
    }
}

/// Something to send to a port to make it answer.
///
/// Sent to every port the owning service registers; a probe marked
/// [`generic`](Self::generic) also goes to open ports that register none of
/// their own.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Probe {
    /// A name for the probe, for authors and for the build's diagnostics.
    pub name: Option<String>,
    /// The bytes to send, authored as a TOML literal string. The escapes `\r`,
    /// `\n`, `\t`, `\0`, `\xHH` and `\\` are decoded to the bytes they denote
    /// before the probe goes on the wire.
    ///
    /// A UDP payload is held to [`MAX_UDP_PROBE_BYTES`] and parsed at build time
    /// as the target service would, since a malformed datagram is silently
    /// dropped and reads as a port that never answered.
    pub payload: String,
    /// The transport carrying the payload: `"tcp"` or `"udp"`. Anything else
    /// warns at build time and the loader drops the probe.
    pub protocol: String,
    /// How common the service behind this probe is, `1..=9`, on the rarity scale
    /// the imported signature corpora are authored on. A probe reaches a port
    /// that did not register it when its rarity is within the scan's intensity
    /// (`rarity <= intensity`), so a rarity of 1 is asked of any port that has
    /// otherwise said nothing and a rarity of 9 only when a scan asks for
    /// everything. See
    /// [`ServiceDetection::probe_intensity`](crate::config::ServiceDetection::probe_intensity).
    ///
    /// Zero means the probe goes only to the ports its own service registered.
    /// Most of the corpus is zero; rarity is assigned per probe, by hand.
    ///
    /// A rarity suits a service that identifies itself no other way: it waits to
    /// be spoken to and answers an HTTP request with silence or a closed socket.
    /// A 1 also means it is what such a port most often turns out to be: Redis,
    /// PostgreSQL and memcached. A Zabbix agent is as silent but seldom moved off
    /// its own port, and is authored at 5.
    #[serde(default)]
    pub rarity: u8,

    /// Whether this probe is also sent to open ports that **register no service**.
    ///
    /// In practice that is one probe, an HTTP request, since HTTP is what an
    /// unrecognised open port usually speaks. Against one home server, seven of
    /// eleven open ports were otherwise unidentified, each costing a two-second
    /// timeout.
    ///
    /// Each generic probe is paid on every unknown port of every scan. TCP only;
    /// `build.rs` refuses a generic UDP probe.
    #[serde(default)]
    pub generic: bool,
}

impl Probe {
    /// An unnamed probe sending `payload` over `protocol`, at rarity zero.
    pub fn new(protocol: impl Into<String>, payload: impl Into<String>) -> Self {
        Self {
            name: None,
            payload: payload.into(),
            protocol: protocol.into(),
            rarity: 0,
            generic: false,
        }
    }
}

/// One `[[match]]` rule: a pattern to run against a response, and what a match
/// on it says about the service behind that response. Each rule becomes one
/// signature in the flat, globally indexed set the engine matches against.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchRule {
    /// A name for the rule, such as `"nginx_server_header"`, for authors and
    /// for reading a diff of the corpus.
    pub name: Option<String>,
    /// The regex a response is matched against.
    ///
    /// Compiled by the linear engine where possible, and by a bounded
    /// backtracking engine for backreferences or look-around, under the
    /// [`MAX_COMPILED_REGEX_BYTES`] cap. A pattern neither engine accepts fails
    /// the build.
    pub pattern: String,
    /// The 1-based capture group holding the version string, where the pattern
    /// captures one. A number the pattern has no group for fails the build.
    pub version_group: Option<u8>,
    /// Who publishes the product, spelled as a report should print it:
    /// `"Apache Software Foundation"`, `"NGINX"`. It counts with `product`
    /// toward how specific a match is when several rules fire on one response.
    pub vendor: Option<String>,
    /// The software a match identifies: `"nginx"`, `"Apache HTTP Server"`. Leave
    /// it empty when the rule names no software.
    pub product: Option<String>,
    /// The field the pattern is written against: `ssh.banner`,
    /// `http_header.server`, `snmp.sys_description`, `favicon.md5`. Imported
    /// with the rule as a record of what it reads; the runtime matches every
    /// text a response yields and does not select on it.
    pub context: Option<String>,
    /// A response this rule is meant to match. The corpus test runs every example
    /// through its own signature.
    pub example: Option<String>,
    /// Everything else the rule states, keyed as the corpus keys it. The engine
    /// reads `service.cpe23`, `service.version`, `service.extrainfo`,
    /// `service.component.product`, `service.component.version`, and the `os.*`
    /// and `hw.device` keys that make up
    /// [`OsMetadata`](crate::fingerprint::os::OsMetadata).
    ///
    /// `service.extrainfo` is detail beyond product and version, such as the
    /// distribution build in an OpenSSH banner. Where a rule states both it and a
    /// component, the report shows `service.extrainfo`.
    ///
    /// Values may be templates. `{capture:1}` is filled from the pattern's first
    /// capture group, and `{service.version}` from the version the match found.
    /// A template with nothing to fill it resolves to nothing.
    pub metadata: Option<HashMap<String, String>>,
}

impl MatchRule {
    /// A rule matching `pattern` and naming nothing beyond the service.
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            name: None,
            pattern: pattern.into(),
            version_group: None,
            vendor: None,
            product: None,
            context: None,
            example: None,
            metadata: None,
        }
    }
}

/// One `assets/fingerprinting` file, whole: the service it describes, what to
/// send that service, and what to make of the answer.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDefinition {
    /// The service this file is about, and the ports it registers.
    pub service: ServiceSignature,
    /// What to send to draw a response. A service that announces itself
    /// unprompted needs none.
    #[serde(default)]
    pub probe: Vec<Probe>,
    /// The rules run against whatever comes back.
    #[serde(default)]
    pub r#match: Vec<MatchRule>,
}

impl ServiceDefinition {
    /// A definition of `service` with no probes and no rules yet.
    pub fn new(service: ServiceSignature) -> Self {
        Self {
            service,
            probe: Vec::new(),
            r#match: Vec::new(),
        }
    }
}

/// Why an authored service definition cannot be used.
///
/// Every variant is a defect that would silently degrade detection.
///
/// The engines' reasons for rejecting a pattern are carried as text, keeping
/// the regex crates' error types out of the public API.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefinitionError {
    /// A rule's pattern is one neither engine can compile.
    Pattern {
        /// Which `[[match]]` rule, counting from zero.
        rule: usize,
        /// What both engines said about it.
        reason: String,
    },
    /// A rule names a version capture group its pattern does not have.
    VersionGroup {
        /// Which `[[match]]` rule, counting from zero.
        rule: usize,
        /// The group the rule asked for.
        group: u8,
        /// How many capturing groups the pattern actually has.
        available: usize,
    },
    /// A probe names a transport this engine does not speak.
    ///
    /// The loader drops such a probe.
    ProbeProtocol {
        /// Which `[[probe]]`, counting from zero.
        probe: usize,
        /// The transport as authored.
        protocol: String,
    },
    /// A probe marked [`generic`](Probe::generic) over something other than TCP.
    ///
    /// Over UDP, `generic` would send the payload to every UDP port in the scan.
    GenericProbeNotTcp {
        /// Which `[[probe]]`, counting from zero.
        probe: usize,
        /// The transport as authored.
        protocol: String,
    },
    /// A UDP probe payload that is empty, or past [`MAX_UDP_PROBE_BYTES`].
    ///
    /// An empty datagram cannot elicit a reply, and an oversized one costs more
    /// than it can return.
    UdpProbeSize {
        /// Which `[[probe]]`, counting from zero.
        probe: usize,
        /// What the payload decoded to.
        bytes: usize,
    },
}

impl std::fmt::Display for DefinitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DefinitionError::Pattern { rule, reason } => {
                write!(f, "match #{rule} has an unusable pattern: {reason}")
            }
            DefinitionError::VersionGroup {
                rule,
                group,
                available,
            } => write!(
                f,
                "match #{rule} references version_group {group}, but the pattern has \
                 {available} {}",
                if *available == 1 {
                    "capture group"
                } else {
                    "capture groups"
                }
            ),
            DefinitionError::ProbeProtocol { probe, protocol } => write!(
                f,
                "probe #{probe} has unknown protocol '{protocol}' (expected 'tcp' or 'udp')"
            ),
            DefinitionError::GenericProbeNotTcp { probe, protocol } => write!(
                f,
                "probe #{probe} is marked generic over {protocol}; a generic probe is sent \
                 to every open port that registers none of its own, which only makes sense \
                 over TCP"
            ),
            DefinitionError::UdpProbeSize { probe, bytes } if *bytes == 0 => write!(
                f,
                "udp probe #{probe} decodes to zero bytes; an empty datagram cannot elicit \
                 a reply"
            ),
            DefinitionError::UdpProbeSize { probe, bytes } => write!(
                f,
                "udp probe #{probe} is {bytes} bytes, over the {MAX_UDP_PROBE_BYTES}-byte \
                 probe ceiling"
            ),
        }
    }
}

impl std::error::Error for DefinitionError {}

impl ServiceDefinition {
    /// Whether this definition is one the engine may use.
    ///
    /// Shared with `build.rs`, so the build and
    /// [`SignatureDb::try_from_definitions`](crate::fingerprint::SignatureDb::try_from_definitions)
    /// accept the same definitions.
    ///
    /// Patterns are compiled here with the runtime's engine selection and
    /// [`MAX_COMPILED_REGEX_BYTES`]. That is the expensive part, so the shipped
    /// database skips it at load.
    ///
    /// The build additionally parses each UDP payload as the target service
    /// would, and warns about maintainability issues.
    pub fn validate(&self) -> Result<(), DefinitionError> {
        for (rule, r#match) in self.r#match.iter().enumerate() {
            let compiled = super::pattern::compile(&r#match.pattern, MAX_COMPILED_REGEX_BYTES)
                .map_err(|reason| DefinitionError::Pattern {
                    rule,
                    reason: reason.to_string(),
                })?;

            // `captures_len` counts group 0 (the whole match) plus each
            // capturing group, so valid indices are `0..captures_len()`.
            if let Some(group) = r#match.version_group
                && usize::from(group) >= compiled.captures_len()
            {
                return Err(DefinitionError::VersionGroup {
                    rule,
                    group,
                    available: compiled.captures_len() - 1,
                });
            }
        }

        for (probe, authored) in self.probe.iter().enumerate() {
            if !matches!(authored.protocol.as_str(), "tcp" | "udp") {
                return Err(DefinitionError::ProbeProtocol {
                    probe,
                    protocol: authored.protocol.clone(),
                });
            }
            if authored.generic && authored.protocol != "tcp" {
                return Err(DefinitionError::GenericProbeNotTcp {
                    probe,
                    protocol: authored.protocol.clone(),
                });
            }
            if authored.protocol == "udp" {
                let bytes = unescape(&authored.payload).len();
                if bytes == 0 || bytes > MAX_UDP_PROBE_BYTES {
                    return Err(DefinitionError::UdpProbeSize { probe, bytes });
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Rule identity
// ---------------------------------------------------------------------------

#[cfg(test)]
mod identity {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn a_corpus_path_becomes_the_slug_an_identifier_is_written_from() {
        assert_eq!(
            corpus_slug(Path::new("assets/fingerprinting/remote/ssh.toml")).as_deref(),
            Some("remote/ssh")
        );
        assert_eq!(
            corpus_slug(Path::new(
                "assets/fingerprinting/imported/rapid7/dns/dns_versionbind.toml"
            ))
            .as_deref(),
            Some("imported/rapid7/dns/dns_versionbind")
        );
    }

    /// Anything outside the corpus has no slug.
    #[test]
    fn a_path_outside_the_corpus_has_no_slug() {
        assert_eq!(corpus_slug(Path::new("src/fingerprint/signature.rs")), None);
        assert_eq!(
            corpus_slug(Path::new("assets/detect/database/redis-unauth.toml")),
            None
        );
        assert_eq!(corpus_slug(Path::new("remote/ssh.toml")), None);
    }

    /// A colon in a rule name is fine; the separator is `#`.
    #[test]
    fn a_name_carrying_a_colon_still_yields_a_splittable_identifier() {
        let id = rule_id("imported/rapid7/dns/dns_versionbind", "ISC BIND: Ubuntu");
        let (slug, name) = id.split_once(RULE_ID_SEPARATOR).expect("one separator");
        assert_eq!(slug, "imported/rapid7/dns/dns_versionbind");
        assert_eq!(name, "ISC BIND: Ubuntu");
    }

    #[test]
    fn a_name_claimed_twice_in_one_file_is_refused() {
        let mut seen = BTreeSet::new();
        assert!(claim_rule_id("remote/ssh", Some("openssh_match"), &mut seen).is_ok());
        assert_eq!(
            claim_rule_id("remote/ssh", Some("openssh_match"), &mut seen),
            Err(RuleIdDefect::Duplicate("openssh_match".to_string()))
        );
    }

    /// The same name in a different file is a different rule.
    #[test]
    fn the_same_name_in_two_files_is_two_identifiers() {
        let mut ssh = BTreeSet::new();
        let mut ftp = BTreeSet::new();
        let a = claim_rule_id("remote/ssh", Some("banner"), &mut ssh).expect("first file");
        let b = claim_rule_id("file_transfer/ftp", Some("banner"), &mut ftp).expect("second file");
        assert_ne!(a, b);
    }

    #[test]
    fn an_unnamed_or_empty_rule_cannot_be_identified() {
        let mut seen = BTreeSet::new();
        assert_eq!(
            claim_rule_id("remote/ssh", None, &mut seen),
            Err(RuleIdDefect::Unnamed)
        );
        assert_eq!(
            claim_rule_id("remote/ssh", Some(""), &mut seen),
            Err(RuleIdDefect::Unnamed)
        );
    }

    #[test]
    fn a_name_carrying_the_separator_is_refused() {
        let mut seen = BTreeSet::new();
        assert_eq!(
            claim_rule_id("remote/ssh", Some("a#b"), &mut seen),
            Err(RuleIdDefect::SeparatorInName("a#b".to_string()))
        );
    }
}
