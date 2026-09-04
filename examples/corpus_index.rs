// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A search index over everything the corpora hold
//!
//! Emits one JSON document describing every probe, match rule, operating-system
//! rule and detection that ships, keyed by the identifier each one is cited
//! under. It is what a catalogue or a website reads to let somebody search the
//! corpus by service, port, vendor, product, CPE, operating system, or the field
//! a rule is written against.
//!
//! ```text
//! cargo run --example corpus_index > index.json
//! ```
//!
//! Run from the crate root, since it reads `assets/` by relative path.
//!
//! ## Why an example rather than a build artifact
//!
//! `build.rs` already parses and validates all of this, so emitting the index
//! there would cost nothing extra. It would also land in `OUT_DIR`, inside
//! `target/`, keyed by a hash, which is a poor place to fetch a deliverable from
//! and a worse one to put in a pipeline. The index is an output somebody asks
//! for, not something every build of the crate should produce.
//!
//! An example is compiled by `cargo check --all-targets`, so this cannot rot
//! against a schema change, which is the property that made `nmap_dump` an
//! example too.
//!
//! ## Facets are derived, never authored
//!
//! Every filter this emits is computed from what a rule already says. Nothing
//! here is a tag somebody has to remember to write, because a hand-maintained
//! taxonomy over four thousand rules goes stale and then quietly misfiles things,
//! which is worse than having no filter at all. A facet that stops being true
//! stops being emitted on the next run.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use zond_engine::detect::{Detections, Gate};
use zond_engine::fingerprint::os::{OsDefinition, Provenance};
use zond_engine::fingerprint::{
    CORPUS_ROOT, MatchRule, Probe, ServiceDefinition, claim_rule_id, context_note, corpus_slug,
    reach_of,
};

/// The whole document, as a reader receives it.
#[derive(Serialize)]
struct Index {
    /// The engine release these corpora shipped with.
    engine_version: &'static str,
    /// How many of each kind of entry follow, so a reader can check a truncated
    /// download rather than silently searching half a corpus.
    counts: BTreeMap<&'static str, usize>,
    entries: Vec<Entry>,
}

/// One searchable thing. Flat and denormalised on purpose: a search index wants
/// one document shape it can facet over, not a graph it has to walk.
#[derive(Serialize)]
struct Entry {
    /// Which corpus this came from: `rule`, `probe`, `os_rule` or `detection`.
    kind: &'static str,
    /// What this entry is cited as, and what a link to it names.
    id: String,
    /// The file it lives in, as a slug, so a reader can group by document.
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<String>,
    /// The top directory of that slug: `remote`, `database`, `imported`, `os`.
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<String>,
    /// What the entry is called inside its file, or a detection's title.
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ports: Vec<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    product: Option<String>,
    /// The field a match rule reads, which is also the axis that says whether
    /// anything in the collection path can currently reach it.
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<String>,
    /// The pattern, the probe payload as authored, or the predicates an
    /// operating-system rule states. What a result card shows.
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    example: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpe: Option<String>,
    /// Everything the entry states about the operating system underneath, keyed
    /// as the corpus keys it.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    os: BTreeMap<String, String>,
    /// Where the definition came from, when it was not authored here.
    #[serde(skip_serializing_if = "Option::is_none")]
    attribution: Option<String>,
    /// Whether the collection path produces the text this rule reads. See
    /// [`reachability_of`]; match rules only.
    #[serde(skip_serializing_if = "Option::is_none")]
    reachability: Option<&'static str>,
    /// What produces the field this rule reads, or what producing it would
    /// take. Carried so a catalogue can say why a rule does not fire.
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<&'static str>,
    /// Computed filters. See the module documentation on why none of these is
    /// authored.
    facets: BTreeSet<String>,
}

impl Entry {
    fn new(kind: &'static str, id: String) -> Self {
        Self {
            kind,
            id,
            file: None,
            category: None,
            name: None,
            service: None,
            ports: Vec::new(),
            protocol: None,
            vendor: None,
            product: None,
            context: None,
            body: None,
            example: None,
            cpe: None,
            os: BTreeMap::new(),
            attribution: None,
            reachability: None,
            note: None,
            facets: BTreeSet::new(),
        }
    }
}

/// The leading path segment of a slug, which is the category the corpus already
/// files a document under.
fn category_of(slug: &str) -> String {
    slug.split('/').next().unwrap_or(slug).to_string()
}

/// What the collection path does with the field a rule reads.
///
/// Delegates to the register in `fingerprint::context`, which is the same
/// declaration `build.rs` refuses an unclassified field against, so the index
/// and the build can never disagree about which rules can fire. This used to be
/// a table of its own here and was wrong the moment a decoder landed.
fn reachability_of(context: Option<&str>) -> &'static str {
    reach_of(context)
        .unwrap_or_else(|| {
            panic!("the corpus reads a field the context register does not classify; build.rs refuses this, so the index should never see it")
        })
        .label()
}

/// Every `.toml` under `root`, sorted, so two runs emit the same document.
fn toml_files(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let listing = match fs::read_dir(&dir) {
            Ok(listing) => listing,
            Err(e) => panic!("failed to read {}: {e}", dir.display()),
        };
        for entry in listing.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "toml") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

fn parse<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    toml::from_str(&text).unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()))
}

/// The service corpus: one entry per probe and one per match rule.
fn service_entries(entries: &mut Vec<Entry>) -> (usize, usize) {
    let root = Path::new(CORPUS_ROOT);
    let (mut rules, mut probes) = (0, 0);

    for path in toml_files(root) {
        // The operating-system rules sit under the same root and are a different
        // schema entirely, so they are read separately below.
        if path.starts_with(root.join("os")) {
            continue;
        }
        let def: ServiceDefinition = parse(&path);
        let slug = corpus_slug(&path).expect("a file under the corpus root");
        let category = category_of(&slug);
        let mut seen = BTreeSet::new();

        for probe in &def.probe {
            let id = claim_rule_id(&slug, probe.name.as_deref(), &mut seen)
                .unwrap_or_else(|d| panic!("{}: a probe {d}", path.display()));
            entries.push(probe_entry(id, &slug, &category, &def, probe));
            probes += 1;
        }
        for rule in &def.r#match {
            let id = claim_rule_id(&slug, rule.name.as_deref(), &mut seen)
                .unwrap_or_else(|d| panic!("{}: a rule {d}", path.display()));
            entries.push(rule_entry(id, &slug, &category, &def, rule));
            rules += 1;
        }
    }
    (rules, probes)
}

fn probe_entry(
    id: String,
    slug: &str,
    category: &str,
    def: &ServiceDefinition,
    probe: &Probe,
) -> Entry {
    let mut entry = Entry::new("probe", id);
    entry.file = Some(slug.to_string());
    entry.category = Some(category.to_string());
    entry.name = probe.name.clone();
    entry.service = Some(def.service.name.clone());
    entry.ports = def.service.default_ports.clone();
    entry.protocol = Some(probe.protocol.clone());
    entry.body = Some(probe.payload.clone());
    entry.attribution = def.service.attribution.clone();

    entry.facets.insert(format!("transport:{}", probe.protocol));
    entry.facets.insert(format!("rarity:{}", probe.rarity));
    if probe.generic {
        entry.facets.insert("generic-probe".into());
    }
    if def.service.attribution.is_some() {
        entry.facets.insert("imported".into());
    }
    entry
}

fn rule_entry(
    id: String,
    slug: &str,
    category: &str,
    def: &ServiceDefinition,
    rule: &MatchRule,
) -> Entry {
    let mut entry = Entry::new("rule", id);
    entry.file = Some(slug.to_string());
    entry.category = Some(category.to_string());
    entry.name = rule.name.clone();
    entry.service = Some(def.service.name.clone());
    entry.ports = def.service.default_ports.clone();
    entry.vendor = rule.vendor.clone();
    entry.product = rule.product.clone();
    entry.context = rule.context.clone();
    entry.body = Some(rule.pattern.clone());
    entry.example = rule.example.clone();
    entry.attribution = def.service.attribution.clone();

    if let Some(metadata) = &rule.metadata {
        for (key, value) in metadata {
            if value.is_empty() {
                continue;
            }
            match key.as_str() {
                "service.cpe23" => entry.cpe = Some(value.clone()),
                key if key.starts_with("os.") || key.starts_with("hw.") => {
                    entry.os.insert(key.to_string(), value.clone());
                }
                _ => {}
            }
        }
    }

    if let Some(speaks) = &def.service.speaks {
        entry.facets.insert(format!("speaks:{speaks}"));
    }
    if let Some(context) = &rule.context {
        entry.facets.insert(format!("context:{context}"));
    }
    let reachability = reachability_of(rule.context.as_deref());
    entry.facets.insert(format!("reachability:{reachability}"));
    entry.reachability = Some(reachability);
    entry.note = context_note(rule.context.as_deref());
    if rule.version_group.is_some() {
        entry.facets.insert("captures-version".into());
    }
    if rule.example.is_some() {
        entry.facets.insert("has-example".into());
    }
    if entry.cpe.is_some() {
        entry.facets.insert("names-cpe".into());
    }
    if !entry.os.is_empty() {
        entry.facets.insert("names-os".into());
    }
    if let Some(family) = entry.os.get("os.family") {
        entry.facets.insert(format!("os-family:{family}"));
    }
    if def.service.attribution.is_some() {
        entry.facets.insert("imported".into());
    }
    entry
}

/// The operating-system stack rules. One `[match]` per file, so the file's own
/// slug is the identifier and there is no name to append.
fn os_entries(entries: &mut Vec<Entry>) -> usize {
    let mut count = 0;
    for path in toml_files(&Path::new(CORPUS_ROOT).join("os")) {
        let def: OsDefinition = parse(&path);
        let slug = corpus_slug(&path).expect("a file under the corpus root");

        let mut entry = Entry::new("os_rule", slug.clone());
        entry.file = Some(slug.clone());
        entry.category = Some("os".to_string());
        entry.name = Some(slug.rsplit('/').next().unwrap_or(&slug).to_string());
        entry.body = def.notes.clone();
        entry.example = def
            .example
            .first()
            .map(|example| example.source.clone())
            .filter(|source| !source.is_empty());

        for (key, value) in [
            ("os.family", def.os.family.as_ref()),
            ("os.vendor", def.os.vendor.as_ref()),
            ("os.product", def.os.product.as_ref()),
            ("os.version", def.os.version.as_ref()),
            ("os.device", def.os.device.as_ref()),
            ("os.cpe23", def.os.cpe.as_ref()),
        ] {
            if let Some(value) = value.filter(|v| !v.is_empty()) {
                entry.os.insert(key.to_string(), value.clone());
            }
        }
        entry.cpe = def.os.cpe.clone();

        // `Provenance` is `#[non_exhaustive]`, so a kind added later reaches the
        // index as its own name rather than being folded into one of these two.
        let provenance = match def.provenance {
            Provenance::Measured => "measured".to_string(),
            Provenance::Published => "published".to_string(),
            other => format!("{other:?}").to_lowercase(),
        };
        entry.facets.insert(format!("provenance:{provenance}"));
        entry
            .facets
            .insert(format!("reply:{:?}", def.r#match.reply));
        if let Some(family) = &def.os.family {
            entry.facets.insert(format!("os-family:{family}"));
        }
        if !def.example.is_empty() {
            entry.facets.insert("has-example".into());
        }

        entries.push(entry);
        count += 1;
    }
    count
}

/// The detections, read from the compiled corpus rather than re-parsed, so the
/// index describes what actually ships rather than what is on disk beside it.
fn detection_entries(entries: &mut Vec<Entry>) -> usize {
    let listing = Detections::embedded().listing();
    let count = listing.len();

    for summary in listing {
        let mut entry = Entry::new("detection", summary.id.clone());
        entry.name = Some(summary.title.clone());
        entry.facets.insert(format!("tier:{}", summary.tier.name()));
        entry
            .facets
            .insert(format!("detection-version:{}", summary.version));
        entry
            .facets
            .insert(format!("class:{}", summary.class.label()));

        // The gate goes into the same columns a signature rule fills, so one
        // query for `redis` finds the signature that names it and the detection
        // that fires on it. A debug rendering of the gate would be neither
        // searchable nor stable.
        let mut services = Vec::new();
        match &summary.gate {
            Gate::Port(rule) => {
                services.extend(rule.service.clone());
                services.extend(rule.services.iter().cloned());
                entry.ports.extend(rule.port);
                entry.ports.extend(rule.ports.iter().copied());
                entry.protocol = rule.protocol.clone();
                if let Some(speaks) = &rule.speaks {
                    entry.facets.insert(format!("speaks:{speaks}"));
                }
            }
            Gate::Host {
                ports_open,
                services: named,
            } => {
                services.extend(named.iter().cloned());
                entry.ports.extend(ports_open.iter().copied());
                entry.facets.insert("host-detection".into());
            }
            _ => {}
        }
        entry.ports.sort_unstable();
        entry.ports.dedup();
        for service in &services {
            entry.facets.insert(format!("service:{service}"));
        }
        entry.service = services.first().cloned();
        entry.body = (!services.is_empty()).then(|| services.join(", "));

        entries.push(entry);
    }
    count
}

fn main() {
    let mut entries = Vec::new();
    let (rules, probes) = service_entries(&mut entries);
    let os_rules = os_entries(&mut entries);
    let detections = detection_entries(&mut entries);

    let index = Index {
        engine_version: env!("CARGO_PKG_VERSION"),
        counts: BTreeMap::from([
            ("rules", rules),
            ("probes", probes),
            ("os_rules", os_rules),
            ("detections", detections),
            ("total", entries.len()),
        ]),
        entries,
    };

    let json = serde_json::to_string_pretty(&index).expect("the index serializes");
    println!("{json}");
}
