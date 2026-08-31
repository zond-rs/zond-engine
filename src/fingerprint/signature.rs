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
//! Compiled into the build script as well as the library, `build.rs` loads this
//! very file with `#[path]`, so the schema the build validates against and the
//! schema the runtime reads are the same code rather than two descriptions of
//! one idea. A field added here is a field both halves see at once, and a field
//! either half could disagree about does not exist.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Upper bound on a single compiled signature's memory footprint.
///
/// The `regex` crate defaults to a 10 MiB compiled-size cap; a few legitimate
/// signatures with large bounded repetitions (e.g. `{1,512}`) compile just past
/// it and would otherwise be dropped. 32 MiB admits them while still bounding
/// worst-case memory. This constant is shared by the runtime matcher and the
/// build-time validator so both accept exactly the same set of patterns.
pub const MAX_COMPILED_REGEX_BYTES: usize = 32 * 1024 * 1024;

/// Upper bound on a single UDP probe payload.
///
/// A probe is sent to one port at a time and can draw at most one reply, so a
/// payload large enough to fragment costs more than it can return - and a
/// scanner that emits large datagrams at many hosts is a traffic source out of
/// proportion to what it learns. Shared by the build-time validator and the
/// runtime tests so both hold probes to the same ceiling.
pub const MAX_UDP_PROBE_BYTES: usize = 512;

/// Decodes the backslash escapes in an authored probe payload into raw bytes.
///
/// Payloads are authored as readable TOML *literal* strings (e.g. `'GET /
/// HTTP/1.1\r\n\r\n'`), so escapes arrive verbatim, a literal `\`, `r`, and
/// would go on the wire malformed if sent as-is. This resolves the common set
/// (`\r`, `\n`, `\t`, `\0`, `\xHH`, `\\`) to the bytes they denote; any other
/// escape is preserved literally so nothing is silently lost.
///
/// Lives beside the schema, rather than in the runtime database, because
/// `build.rs` decodes payloads to validate them and the runtime decodes them to
/// send: two readings of the same authored bytes that must never disagree about
/// what was written.
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
                    // Malformed \xHH: keep the marker, best-effort.
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSignature {
    /// The service's canonical name, the one a report prints and every rule and
    /// probe in the file registers under.
    pub name: String,
    /// The ports this service claims. Each one indexes the file's rules and
    /// probes under that number in
    /// [`SignatureDb`](crate::fingerprint::SignatureDb), and the first service
    /// to claim a number is the one that gives it its primary name.
    ///
    /// An empty list is a finished definition rather than an omission: a file
    /// with no ports holds banner rules reached by global matching, where the
    /// text decides what the service is and the number never enters into it.
    pub default_ports: Vec<u16>,
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
    /// The corpus gives a product its own service name, so a Grafana server is
    /// identified as `grafana` and a plain web server on the same port as
    /// `http`. Without this, a detection written about HTTP has to name every
    /// product that speaks it, and is wrong again the next time the corpus
    /// grows. A detection names the protocol instead, through
    /// [`Rule::speaks`](crate::detect::manifest::Rule::speaks).
    ///
    /// It says what this signature matched on, not what the product offers.
    /// Riak, Neo4j and RethinkDB all have HTTP APIs and are fingerprinted here
    /// by their binary wire protocols, so none of them sets it: a port
    /// identified from those bytes is not a port answering HTTP.
    #[serde(default)]
    pub speaks: Option<String>,
}

/// Something to send to a port to make it answer.
///
/// Sent to every port the owning service registers; a probe marked
/// [`generic`](Self::generic) also goes to open ports that register none of
/// their own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Probe {
    /// A name for the probe, for authors and for the build's diagnostics.
    pub name: Option<String>,
    /// The bytes to send, authored as a TOML literal string. The escapes `\r`,
    /// `\n`, `\t`, `\0`, `\xHH` and `\\` are decoded to the bytes they denote
    /// before the probe goes on the wire.
    ///
    /// A UDP payload is held to [`MAX_UDP_PROBE_BYTES`] and parsed at build
    /// time the way the target service would parse it, because a malformed
    /// datagram is dropped in silence and a scan reads that silence as a
    /// filtered port.
    pub payload: String,
    /// The transport carrying the payload: `"tcp"` or `"udp"`. Anything else
    /// warns at build time, and the loader drops the probe rather than guess
    /// which transport was meant.
    pub protocol: String,
    /// How aggressive/uncommon this probe is, `0..=9`, on the rarity scale the
    /// imported signature corpora use. A probe is sent only when its rarity is
    /// within the scan's
    /// intensity level (`rarity <= intensity`), so low-rarity probes go out on
    /// every scan and high-rarity ones only when explicitly asked for.
    ///
    /// Reserved ahead of the intensity and softmatch work: the runtime does not
    /// yet gate on it. `#[serde(default)]` makes it backward-compatible, every
    /// existing probe deserializes at rarity `0` (common, always sent), so
    /// current behaviour is unchanged until an intensity cap is wired in.
    #[serde(default)]
    pub rarity: u8,

    /// Whether this probe is worth sending to a port **nothing knows anything
    /// about**, rather than only to the ports its service registered.
    ///
    /// An ordinary probe is addressed: it is sent to port 5432 because a service
    /// claimed 5432, and it means nothing anywhere else. A generic probe is a
    /// question worth asking of any open port at all, because the answer
    /// identifies whatever gave it.
    ///
    /// In practice that is one probe, an HTTP request, and the reason is that
    /// HTTP is what an unrecognised open port usually turns out to be speaking.
    /// A scan that sends nothing to those ports learns nothing about them and
    /// still pays a full timeout finding that out; measured against one
    /// ordinary home server, seven of eleven open ports were unidentified and
    /// each cost two seconds to leave unidentified.
    ///
    /// Adding a second one is a real cost, paid on every unknown port of every
    /// scan, so it wants the same evidence the first had. TCP only: a generic
    /// UDP probe would be a payload sent to every UDP port in the scan, which is
    /// a different and much larger claim. `build.rs` refuses one.
    #[serde(default)]
    pub generic: bool,
}

/// One `[[match]]` rule: a pattern to run against a response, and what a match
/// on it says about the service behind that response. Each rule becomes one
/// signature in the flat, globally indexed set the engine matches against.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchRule {
    /// A name for the rule, such as `"nginx_server_header"`, for authors and
    /// for reading a diff of the corpus.
    pub name: Option<String>,
    /// The regex a response is matched against.
    ///
    /// Compiled by the linear engine where it can be, and by a bounded
    /// backtracking engine when it uses backreferences or lookaround, under the
    /// [`MAX_COMPILED_REGEX_BYTES`] size cap. A pattern neither engine accepts
    /// fails the build instead of going missing from a scan.
    pub pattern: String,
    /// The 1-based capture group holding the version string, where the pattern
    /// captures one. A number the pattern has no group for fails the build.
    pub version_group: Option<u8>,
    /// Who publishes the product, spelled as a report should print it:
    /// `"Apache Software Foundation"`, `"NGINX"`. It counts with `product`
    /// toward how specific a match is when several rules fire on one response.
    pub vendor: Option<String>,
    /// The software a match identifies: `"nginx"`, `"Apache HTTP Server"`. A
    /// rule that names none leaves the field empty rather than repeating the
    /// service name back.
    pub product: Option<String>,
    /// The field the pattern is written against: `ssh.banner`,
    /// `http_header.server`, `snmp.sys_description`, `favicon.md5`. Imported
    /// with the rule as a record of what it reads; the runtime matches every
    /// text a response yields and does not select on it.
    pub context: Option<String>,
    /// A response this rule is meant to match, recorded beside it. The corpus
    /// test runs every example through its own signature, which is what catches
    /// a pattern that quietly stopped matching what it was written for.
    pub example: Option<String>,
    /// Everything else the rule states, keyed as the corpus keys it. The engine
    /// reads `service.cpe23`, `service.version`, and the `os.*` and `hw.device`
    /// keys that make up
    /// [`OsMetadata`](crate::fingerprint::os::OsMetadata).
    ///
    /// Values may be templates. An `os.*` value written `{capture:1}` is filled
    /// from the pattern's first capture group when the rule fires, and a
    /// `service.cpe23` naming `{service.version}` is filled from the version
    /// the match found. A template with nothing to fill it resolves to nothing
    /// at all, rather than to a half-built value a consumer would try to match
    /// on.
    pub metadata: Option<HashMap<String, String>>,
}

/// One `assets/fingerprinting` file, whole: the service it describes, what to
/// send that service, and what to make of the answer.
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

/// Why an authored service definition cannot be used.
///
/// Every variant is a defect that degrades detection silently. A pattern
/// neither engine compiles is a signature that never fires; a `version_group`
/// past the pattern's groups is a version never captured; a probe over a
/// transport this engine does not speak is a probe never sent. None of them is
/// distinguishable, from a scan's output, from a service that simply was not
/// there.
///
/// The engine's own reason for rejecting a pattern is carried as text rather
/// than as the two regex crates' error types, which are foreign and pre-1.0 and
/// have no business in a semver contract. Which rule and which defect are typed,
/// because those are what a caller acts on.
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
    /// The loader drops such a probe rather than guessing which was meant, so
    /// without this the only symptom is a probe that is never sent.
    ProbeProtocol {
        /// Which `[[probe]]`, counting from zero.
        probe: usize,
        /// The transport as authored.
        protocol: String,
    },
    /// A probe marked [`generic`](Probe::generic) over something other than TCP.
    ///
    /// `generic` means "send this to any open port with nothing else to send",
    /// and over UDP that is a payload aimed at every UDP port in the scan: a
    /// different and much larger claim than the one the flag is for, and one
    /// nobody would make by ticking a boolean.
    GenericProbeNotTcp {
        /// Which `[[probe]]`, counting from zero.
        probe: usize,
        /// The transport as authored.
        protocol: String,
    },
    /// A UDP probe payload that is empty, or past [`MAX_UDP_PROBE_BYTES`].
    ///
    /// An empty datagram cannot elicit a reply, and an oversized one costs more
    /// than it can return. Both read as a filtered port.
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
                 {available} capture group(s)"
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
    /// Shared with `build.rs`, which loads this very file, so the definitions
    /// the build accepts and the definitions
    /// [`SignatureDb::try_from_definitions`](crate::fingerprint::SignatureDb::try_from_definitions)
    /// accepts are one set rather than two descriptions of one idea.
    ///
    /// Patterns are compiled here, through the same engine selection and the
    /// same [`MAX_COMPILED_REGEX_BYTES`] the runtime uses, which is what makes
    /// "the build accepted it" and "the runtime can match it" the same
    /// statement. It is the expensive part, and it is why the shipped database
    /// does not run this again at load: `build.rs` already did.
    ///
    /// The build checks two further things this cannot. It parses each UDP
    /// payload the way the target service would, which needs protocol parsers
    /// the runtime does not carry, and it warns about softer matters that make a
    /// corpus hard to maintain rather than wrong.
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
