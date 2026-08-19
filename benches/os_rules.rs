// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Answers "does a rule for this already exist?" across every corpus at once.
//!
//! Before adding a rule, somebody has to know what is already there. That
//! question is genuinely hard to answer by looking, and no directory layout fixes
//! it, because the answer is spread across three corpora that work in different
//! ways and one of the files holding it is well over two thousand lines long:
//!
//! * **stack rules** in `assets/fingerprinting/os/` — predicates over a typed
//!   feature vector read off a TCP reply. This crate's own, and the only ones a
//!   contributor is likely to think of first.
//! * **operating-system name rules** in the imported corpus — regexes over an
//!   OS *string* a service reported, such as an SMB or SNMP identification.
//! * **service rules** throughout the imported corpus — regexes over a service
//!   banner, more than half of which name an operating system as a side effect.
//!   These are service signatures and stay where they are: they are matched by
//!   the service pipeline, and the operating system is something they mention.
//!
//! Colocating them would mean either duplicating the third set or breaking
//! service detection, and would separate the imported files from the attribution
//! that belongs with them. So they stay put, and this reads all three.
//!
//! ```text
//! cargo bench --no-run --bench os_rules
//! target/release/deps/os_rules-<hash> windows
//! ```
//!
//! No privileges, no network: it reads the asset tree. The query matches any
//! part of a family, vendor, product or version, case-insensitively, so
//! `os_rules 2003` and `os_rules microsoft` both work. With no query it prints
//! every family the corpora know, which is the other question worth asking
//! before adding anything.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use zond_engine::fingerprinting::ServiceDefinition;
use zond_engine::fingerprinting::os::OsDefinition;

/// Where the corpora live, relative to the crate root.
const ASSETS: &str = "assets/fingerprinting";

/// One rule that names an operating system, wherever it came from.
struct Found {
    /// Which corpus, for the heading it is printed under.
    kind: &'static str,
    file: PathBuf,
    /// The family, and the finer detail where the rule gave any.
    names: String,
    /// What the rule matches on: predicates for a stack rule, a pattern for the
    /// others. What a contributor needs in order to decide "is mine the same?"
    matches_on: String,
}

fn main() {
    let query = std::env::args().nth(1).unwrap_or_default().to_lowercase();

    let root = Path::new(ASSETS);
    if !root.is_dir() {
        eprintln!("run this from the crate root: {ASSETS} is not a directory here");
        std::process::exit(2);
    }

    let mut files = Vec::new();
    collect(root, &mut files);
    files.sort();

    let mut found = Vec::new();
    for file in &files {
        let Ok(text) = fs::read_to_string(file) else {
            continue;
        };
        // Which schema a file is, decided by which one parses. The two are
        // disjoint enough that this cannot be ambiguous: a stack rule has a
        // single `[match]` table and a service definition has a `[[match]]`
        // array.
        if let Ok(rule) = toml::from_str::<OsDefinition>(&text) {
            found.push(from_stack_rule(file, &rule));
        } else if let Ok(service) = toml::from_str::<ServiceDefinition>(&text) {
            found.extend(from_service(file, &service));
        }
    }

    let matching: Vec<&Found> = found
        .iter()
        .filter(|entry| query.is_empty() || entry.names.to_lowercase().contains(&query))
        .collect();

    if query.is_empty() {
        print_families(&found);
        return;
    }

    if matching.is_empty() {
        println!("Nothing in any corpus names anything matching {query:?}.");
        println!("Adding it is a new rule rather than an edit to an existing one.");
        println!();
        println!("Where it goes depends on what it reads:");
        println!("  a TCP reply's shape         -> assets/fingerprinting/os/");
        println!("  an OS string from SMB/SNMP  -> the imported operating-system corpus");
        println!("  a service banner            -> the imported corpus for that protocol");
        return;
    }

    let mut by_kind: BTreeMap<&str, Vec<&Found>> = BTreeMap::new();
    for entry in &matching {
        by_kind.entry(entry.kind).or_default().push(entry);
    }

    for (kind, entries) in &by_kind {
        println!("\n{kind} ({} rule(s))", entries.len());
        // Grouped by file, since that is what somebody is about to open.
        let mut by_file: BTreeMap<&PathBuf, Vec<&&Found>> = BTreeMap::new();
        for entry in entries {
            by_file.entry(&entry.file).or_default().push(entry);
        }
        for (file, entries) in by_file {
            println!("  {}", file.display());
            for entry in entries.iter().take(12) {
                println!("      {:<44} {}", entry.names, entry.matches_on);
            }
            if entries.len() > 12 {
                println!("      ... and {} more in this file", entries.len() - 12);
            }
        }
    }

    println!(
        "\n{} rule(s) already name something matching {query:?}.",
        matching.len()
    );
    println!("Check whether yours is one of them before adding it.");
    println!("A second rule saying the same thing is not a second piece of evidence,");
    println!("and two that disagree about a family resolve to no answer at all.");
}

/// Every family any corpus knows, which is the question worth asking before
/// deciding a rule is missing.
fn print_families(found: &[Found]) {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut templated = 0usize;
    for entry in found {
        // The family is the first segment of the name path.
        let family = entry.names.split(" / ").next().unwrap_or(&entry.names);
        // A family that is itself a template is not a family: the rule builds its
        // name out of what the pattern captured, so it belongs to whatever the
        // banner said rather than to any fixed one. Counting those under a
        // literal `{capture:1}` heading would invent a large and non-existent
        // operating system.
        if family.contains('{') {
            templated += 1;
            continue;
        }
        *counts.entry(family).or_default() += 1;
    }

    println!(
        "{} rule(s) across all corpora name an operating system.\n",
        found.len()
    );
    println!("{:<40} rules", "family");
    let mut ordered: Vec<(&&str, &usize)> = counts.iter().collect();
    ordered.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (family, count) in ordered.iter().take(40) {
        println!("{family:<40} {count}");
    }
    if ordered.len() > 40 {
        println!("... and {} more families", ordered.len() - 40);
    }
    if templated > 0 {
        println!();
        println!("{templated} further rule(s) name a family built from what their pattern");
        println!("captured, so they belong to whatever the banner said rather than to");
        println!("any family that can be listed here.");
    }
    println!("\nPass a query to see the rules themselves: os_rules windows");
}

fn from_stack_rule(file: &Path, rule: &OsDefinition) -> Found {
    let mut names = rule.os.family.clone();
    for part in [&rule.os.product, &rule.os.version].into_iter().flatten() {
        names.push_str(" / ");
        names.push_str(part);
    }

    // The predicates, rendered the way the file states them, so a contributor can
    // see at a glance whether their shape is already covered.
    let m = &rule.r#match;
    let mut predicates = vec![format!("{:?}", m.reply).to_lowercase()];
    if let Some(layout) = m.option_layout.as_ref().and_then(|p| p.equals.clone()) {
        predicates.push(format!("layout={layout}"));
    }
    if let Some(hops) = m.initial_hops.as_ref().and_then(|p| p.equals) {
        predicates.push(format!("hops={hops}"));
    }
    if let Some(scale) = m.window_scale.as_ref().and_then(|p| p.equals) {
        predicates.push(format!("ws={scale}"));
    }

    Found {
        kind: "stack rules — predicates over a TCP reply",
        file: file.to_path_buf(),
        names,
        matches_on: predicates.join(" "),
    }
}

fn from_service(file: &Path, service: &ServiceDefinition) -> Vec<Found> {
    let named_os = file
        .components()
        .any(|c| c.as_os_str() == "operating" || c.as_os_str() == "architecture");

    service
        .r#match
        .iter()
        .filter_map(|rule| {
            let metadata = rule.metadata.as_ref()?;
            let value = |key: &str| metadata.get(key).filter(|v| !v.is_empty());

            let family = value("os.family").or_else(|| value("os.product"))?;
            let mut names = family.clone();
            for key in ["os.product", "os.version"] {
                if let Some(part) = value(key)
                    && part != family
                {
                    names.push_str(" / ");
                    names.push_str(part);
                }
            }

            Some(Found {
                kind: if named_os {
                    "operating-system name rules — over a reported OS string"
                } else {
                    "service rules — over a banner, naming an OS as a side effect"
                },
                file: file.to_path_buf(),
                names,
                matches_on: truncate(&rule.pattern, 58),
            })
        })
        .collect()
}

fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    let kept: String = text.chars().take(width.saturating_sub(1)).collect();
    format!("{kept}…")
}

fn collect(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, files);
        } else if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            files.push(path);
        }
    }
}
