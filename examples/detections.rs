// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Writing detections, and running somebody else's
//!
//! Fingerprinting names a service. A detection says what is wrong with it, and
//! this is how one is written, validated, loaded and published.
//!
//! ```text
//! cargo run --example detections
//! ```
//!
//! Runs anywhere, needs no privileges and touches no network. Every detection
//! here is compiled through the same builder a scan uses, and the bundle is
//! signed and verified with a key generated on the spot.
//!
//! ## Two tiers, and the choice between them
//!
//! A [flow](zond_engine::detect::flow) is a detection authored as data: a bounded
//! sequence of probe-and-match steps ending in a typed finding. It carries no
//! code, cannot loop, cannot compute, and cannot exceed the budget it declares.
//! Most detections are one probe and one match, and those should be flows.
//!
//! A [compute module](zond_engine::detect::compute) is for the rest: real
//! parsing, a stateful exchange, a verdict folded out of several conditions. It
//! is code, and it runs in a capability sandbox where it reaches the world only
//! through the verbs the host injects.
//!
//! ## What a detection asks for, and what it is granted
//!
//! Every detection declares a class: `passive` sends nothing, `active-benign`
//! exchanges bytes with the one scanned socket, and `active-mutating`, `exploit`
//! and `dos` each do more to the target than the one before. That is a request.
//! The operator's [envelope](zond_engine::config::envelope::DetectionEnvelope)
//! is the grant, and it defaults to `active-benign`, so a detection above it is
//! compiled and then never run until somebody raises the ceiling.
//!
//! Nothing a detection says about itself changes what it is handed.

use std::collections::BTreeMap;
use std::io::Write;

use zond_engine::detect::bundle::{Bundle, Tier, content_hash};
use zond_engine::detect::{Detections, Gate};
use zond_engine::signature::{Domain, Signing, SigningKey};

// ── Tier 1: a flow ──────────────────────────────────────────────────────────
//
// The shape most detections take. One probe, one match, one finding.
//
// `[detection.when]` is the gate: this runs only against a port the scan
// identified as Redis over TCP, so a scan of a network with no Redis on it
// spends nothing on this detection at all.
//
// `bind` captures out of the reply into a variable, and `{version}` in the
// finding is that capture. A step that does not match halts the flow unless it
// says `on_no_match = "continue"`.
const REDIS: &str = r##"
[detection]
id      = "example-redis-unauth"
version = "1.0.0"
title   = "Unauthenticated Redis access"

[detection.when]
service  = "redis"
protocol = "tcp"

[detection.capabilities]
class      = "active-benign"
speak      = "target"
max_bytes  = 8192
max_millis = 2000

[[step]]
send   = "INFO\r\n"
expect = "# Server"
bind   = { version = "redis_version:(?<version>[0-9.]+)" }

  [[step.finding]]
  when       = "matched"
  severity   = "high"
  summary    = "Redis answered INFO without authentication"
  detail     = "Server version {version} is reachable without a password."
  references = [{ cwe = 306 }]
"##;

// A flow written about software nobody else will ever ship a check for, which is
// the case that makes this whole mechanism worth having.
//
// `speaks = "http"` gates on the protocol rather than on a product name. The
// fingerprint corpus gives a recognised application its own service name, so a
// gate naming `http` would skip every port the corpus could put a better name
// to; asking for what a service *speaks* covers both.
const IN_HOUSE: &str = r#"
[detection]
id      = "example-metrics-pprof"
version = "1.0.0"
title   = "Internal metrics daemon exposes pprof"

[detection.when]
speaks = "http"
ports  = [9110, 9111]

[detection.capabilities]
class      = "active-benign"
speak      = "target"
max_bytes  = 8192
max_millis = 2000

[[step]]
send   = "GET /debug/pprof/ HTTP/1.0\r\n\r\n"
expect = "Types of profiles available"
bind   = { build = "X-Acme-Build: (?<build>[0-9a-f]{7,40})" }

  [[step.finding]]
  when       = "matched"
  severity   = "high"
  summary    = "pprof is reachable on the metrics port"
  detail     = "Build {build} serves /debug/pprof to anyone who can reach the port."
  references = [{ cwe = 200 }]
"#;

// ── Tier 2: a compute module ────────────────────────────────────────────────
//
// This one earns its tier: the verdict is a count folded into a severity, which
// a single match cannot express.
//
// The entry point is `analyze(ctx, responses)`, returning an array of findings.
// `responses` is what the scan already gathered, and `text` decodes a blob. A
// `passive` module gets no `speak`, so this cannot touch the network however it
// is written.
const HEADERS: &str = r#"
[detection]
id      = "example-missing-security-headers"
version = "1.0.0"
title   = "Missing HTTP security headers"

[detection.when]
speaks = "http"

[detection.capabilities]
class = "passive"

[compute]
language = "rhai"
source = '''
fn analyze(ctx, responses) {
    if responses.len() == 0 {
        return [];
    }

    let response = text(responses[0]).to_lower();
    if !response.contains("http/") {
        return [];
    }

    let headers = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
    ];

    let missing = [];
    for header in headers {
        if !response.contains(header) {
            missing.push(header);
        }
    }

    if missing.len() == 0 {
        return [];
    }

    [ #{
        severity: if missing.len() >= 3 { "medium" } else { "low" },
        summary: "the server omits " + missing.len() + " baseline security headers",
        detail: "Absent: " + missing,
    } ]
}
'''
"#;

// ── The host tier ───────────────────────────────────────────────────────────
//
// A conclusion drawn from what a host presents as a whole rather than from any
// one port. It sends nothing, so it declares no class.
const DOMAIN_CONTROLLER: &str = r#"
[detection]
id      = "example-domain-controller"
version = "1.0.0"
title   = "Host presents as a domain controller"

[detection.host]
ports_open = [88, 389, 445]

[[finding]]
severity = "info"
summary  = "this host answers on Kerberos, LDAP and SMB together"
detail   = "The combination is what a domain controller presents; it is worth knowing which machine it is."
"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut out = std::io::stdout().lock();

    written_by_hand(&mut out)?;
    read_as_files(&mut out)?;
    published_as_a_bundle(&mut out)?;
    listed(&mut out)?;

    Ok(())
}

/// Adding detections the caller wrote, one at a time.
///
/// Each call validates and compiles as it goes, so a source the build would have
/// refused is refused here with the same objection. The corpus that comes out is
/// what a scan runs: pass it to
/// [`scan`](zond_engine::scanner::scan) alongside the config.
fn written_by_hand(out: &mut dyn Write) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(out, "== written by hand ==")?;

    let corpus = Detections::builder()
        .flow(REDIS, &content_hash(REDIS))?
        .flow(IN_HOUSE, &content_hash(IN_HOUSE))?
        .compute(HEADERS, &content_hash(HEADERS))?
        .host(DOMAIN_CONTROLLER, &content_hash(DOMAIN_CONTROLLER))?
        .build();

    writeln!(
        out,
        "{} detections, shipped corpus included",
        corpus.listing().len()
    )?;

    // The other half of the API: the shipped detections left out, so a scan runs
    // only what was named. What an author wants while getting one file right.
    let mine = Detections::builder()
        .without_embedded()
        .flow(IN_HOUSE, &content_hash(IN_HOUSE))?
        .build();

    writeln!(out, "{} detection, mine alone\n", mine.listing().len())?;

    Ok(())
}

/// Adding a whole directory at once, which is what a front end does.
///
/// The engine opens nothing: `sources` takes names and contents, and where they
/// came from is the caller's business. A name ending `.toml` is a detection and
/// the tier comes out of the document; anything else is a body a `[compute]`
/// section may reference by name, which is how a module keeps its code in a file
/// of its own with editor support.
fn read_as_files(out: &mut dyn Write) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(out, "== read as files ==")?;

    // What a directory read would have produced. Substitute `std::fs::read_dir`
    // and `read_to_string` and nothing else changes.
    let mut sources = BTreeMap::new();
    sources.insert("redis-unauth.toml".to_string(), REDIS.to_string());
    sources.insert(
        "domain-controller.toml".to_string(),
        DOMAIN_CONTROLLER.to_string(),
    );
    sources.insert(
        "headers.toml".to_string(),
        r#"
[detection]
id      = "example-headers-out-of-line"
version = "1.0.0"
title   = "Missing HTTP security headers"
[detection.when]
speaks = "http"
[detection.capabilities]
class = "passive"
[compute]
language = "rhai"
body     = "headers.rhai"
"#
        .to_string(),
    );
    sources.insert(
        "headers.rhai".to_string(),
        "fn analyze(ctx, responses) { [] }".to_string(),
    );

    let corpus = Detections::builder()
        .without_embedded()
        .sources(&sources)?
        .build();

    writeln!(
        out,
        "{} detections from 3 documents",
        corpus.listing().len()
    )?;

    // An objection names the document that drew it, which is what makes a
    // directory of thirty files debuggable.
    let mut broken = BTreeMap::new();
    broken.insert(
        "typo.toml".to_string(),
        "[detection]\nid = \"x\"\nversion = \"1.0.0\"\ntitle = \"x\"\n".to_string(),
    );
    match Detections::builder().without_embedded().sources(&broken) {
        Ok(_) => writeln!(
            out,
            "a document naming no tier was accepted, which is a defect"
        )?,
        Err(error) => writeln!(out, "refused: {error}\n")?,
    }

    Ok(())
}

/// Publishing a set for somebody else to run, and loading one somebody else
/// published.
///
/// The three calls above take bytes the caller chose, which is their own act.
/// This is the other door, and it is the only way a stranger's detections enter a
/// corpus: the manifest names every detection and the hash of its source, a
/// signature covers the manifest, and the caller names the key they trust. An
/// attacker serving the files cannot drop the one that would have found them,
/// because membership is inside the signature and not merely the bytes.
fn published_as_a_bundle(out: &mut dyn Write) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(out, "== published as a bundle ==")?;

    // The publisher's side. A real one keeps its key somewhere better than a
    // local variable and writes the three files out for distribution.
    let mut sources = BTreeMap::new();
    sources.insert(
        "redis-unauth.toml".to_string(),
        (Tier::Flow, REDIS.to_string()),
    );
    sources.insert(
        "domain-controller.toml".to_string(),
        (Tier::Host, DOMAIN_CONTROLLER.to_string()),
    );

    let manifest = Bundle::manifest("acme-security", "2026.1", &sources);

    let (_pkcs8, key) = SigningKey::generate()?;
    let mut sink = Vec::new();
    let mut writer = Signing::new(&mut sink);
    writer.write_all(manifest.as_bytes())?;
    let signature = writer.finish(&key, Domain::DETECTIONS);

    writeln!(
        out,
        "signed {} detections as acme-security 2026.1",
        sources.len()
    )?;

    // The recipient's side. The key arrives by some route other than the bundle:
    // verifying against the key named inside the document being verified accepts
    // anything an attacker re-signed.
    let trusted = key.public_key();

    let delivered: BTreeMap<String, String> = sources
        .iter()
        .map(|(name, (_, source))| (name.clone(), source.clone()))
        .collect();

    let bundle = Bundle::verified(&manifest, &signature, &trusted, delivered)?;
    let corpus = Detections::builder()
        .without_embedded()
        .bundle(bundle)?
        .build();

    writeln!(
        out,
        "verified and loaded {} detections",
        corpus.listing().len()
    )?;

    // A signature says who published a detection, never that it is well-formed.
    // One from a trusted key is held to exactly the validation a hand-written
    // source is, and a tampered source never reaches the compiler at all.
    let mut tampered: BTreeMap<String, String> = sources
        .iter()
        .map(|(name, (_, source))| (name.clone(), source.clone()))
        .collect();
    tampered.insert(
        "redis-unauth.toml".to_string(),
        REDIS.replace("severity   = \"high\"", "severity   = \"low\""),
    );

    match Bundle::verified(&manifest, &signature, &trusted, tampered) {
        Ok(_) => writeln!(out, "an altered source verified, which is a defect")?,
        Err(error) => writeln!(out, "refused: {error}\n")?,
    }

    Ok(())
}

/// What a scan would run, which is what a front end lists and an author checks.
///
/// A detection in the listing is one the corpus compiled. Whether it *runs* is
/// decided twice more: by its class against the operator's envelope, and then by
/// its gate against each port.
fn listed(out: &mut dyn Write) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(out, "== what a scan would run ==")?;

    let corpus = Detections::builder()
        .without_embedded()
        .flow(REDIS, &content_hash(REDIS))?
        .compute(HEADERS, &content_hash(HEADERS))?
        .host(DOMAIN_CONTROLLER, &content_hash(DOMAIN_CONTROLLER))?
        .build();

    for detection in corpus.listing() {
        let class = detection.class.label();

        let gate = match &detection.gate {
            Gate::Port(rule) => {
                let mut parts = Vec::new();
                if let Some(service) = &rule.service {
                    parts.push(format!("service {service}"));
                }
                if let Some(speaks) = &rule.speaks {
                    parts.push(format!("speaks {speaks}"));
                }
                if !rule.ports.is_empty() {
                    parts.push(format!("ports {:?}", rule.ports));
                }
                if parts.is_empty() {
                    "any port".to_string()
                } else {
                    parts.join(", ")
                }
            }
            Gate::Host {
                ports_open,
                services,
            } => {
                let mut parts = Vec::new();
                if !ports_open.is_empty() {
                    parts.push(format!("ports open {ports_open:?}"));
                }
                if !services.is_empty() {
                    parts.push(format!("services {services:?}"));
                }
                parts.join(", ")
            }
            // `Gate` is non-exhaustive: a tier added later gates on something
            // this arm has not seen, and a listing should print it as unknown
            // rather than stop compiling.
            _ => "?".to_string(),
        };

        writeln!(
            out,
            "  {:<36} {:<8} {:<14} {gate}",
            detection.id,
            detection.tier.name(),
            class
        )?;
    }

    Ok(())
}
