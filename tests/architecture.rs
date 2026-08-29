// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The module order, as a test rather than a comment
//!
//! `src/lib.rs` describes the crate as a list where each module depends only on
//! the ones above it. Until this file existed that was a claim in a doc comment,
//! and by 2026-08 it had six pairs of modules depending on each other in both
//! directions.
//!
//! These two tests read every `use crate::…` in the library and check the claim.
//! [`ORDER`] is the list, and adding a module means adding it there.
//!
//! Test code is excluded. A test reaching sideways for a fixture says nothing
//! about how the crate is arranged.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Every top-level module, lowest first. A module may import from those before
/// it and never from those after.
///
/// Keep in step with the layout section of `src/lib.rs`, which says the same
/// thing in prose for a reader arriving at the documentation.
const ORDER: &[&str] = &[
    "format",
    "logging",
    "model",
    "version",
    "protocols",
    "system",
    "fingerprint",
    "transport",
    "evasion",
    "config",
    "report",
    "resolve",
    "diff",
    "record",
    "cve",
    "detect",
    "merge",
    "journal",
    "scanner",
    "export",
    "import",
];

/// Which top-level module a source file belongs to.
fn owner(path: &Path) -> String {
    let rel = path.strip_prefix("src").expect("a path under src");
    let first = rel.components().next().expect("a non-empty path");
    Path::new(first.as_os_str())
        .file_stem()
        .expect("a file stem")
        .to_string_lossy()
        .into_owned()
}

/// The file's source with its test modules removed.
///
/// Whole-file test modules are gated at the declaration site rather than inside,
/// so a file whose own first item is a `#[cfg(test)]` module contributes nothing.
fn production_source(text: &str) -> &str {
    let inline = text.find("#[cfg(test)]");
    let gated = text.find("#[cfg(all(test");
    match (inline, gated) {
        (Some(a), Some(b)) => &text[..a.min(b)],
        (Some(a), None) => &text[..a],
        (None, Some(b)) => &text[..b],
        (None, None) => text,
    }
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("src is readable") {
        let path = entry.expect("a readable entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every `owner -> imported` edge in the library's production code.
fn edges() -> BTreeMap<String, BTreeSet<String>> {
    let known: BTreeSet<&str> = ORDER.iter().copied().collect();
    let mut files = Vec::new();
    rust_files(Path::new("src"), &mut files);

    let mut graph: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for file in files {
        let owner = owner(&file);
        if owner == "lib" {
            continue;
        }
        let text = fs::read_to_string(&file).expect("a readable source file");
        for line in production_source(&text).lines() {
            let Some(rest) = line.trim_start().strip_prefix("use crate::") else {
                continue;
            };
            let rest = rest.trim_start_matches('{');
            let imported: String = rest
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || *c == '_')
                .collect();
            if imported != owner && known.contains(imported.as_str()) {
                graph.entry(owner.clone()).or_default().insert(imported);
            }
        }
    }
    graph
}

#[test]
fn no_module_depends_on_one_declared_after_it() {
    let rank: BTreeMap<&str, usize> = ORDER.iter().enumerate().map(|(i, m)| (*m, i)).collect();
    let graph = edges();

    let mut violations = Vec::new();
    for (owner, imports) in &graph {
        let Some(&from) = rank.get(owner.as_str()) else {
            panic!("module `{owner}` is missing from ORDER in tests/architecture.rs");
        };
        for imported in imports {
            let to = rank[imported.as_str()];
            if to > from {
                violations.push(format!(
                    "  {owner} (position {from}) imports {imported} (position {to})"
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "modules must import only from those declared before them in ORDER:\n{}\n\nEither the \
         import belongs somewhere lower, or ORDER and the layout section of src/lib.rs need to \
         change together.",
        violations.join("\n")
    );
}

#[test]
fn the_module_graph_is_acyclic() {
    let graph = edges();
    let mut state: BTreeMap<String, u8> = BTreeMap::new();
    let mut found = Vec::new();

    fn walk(
        node: &str,
        graph: &BTreeMap<String, BTreeSet<String>>,
        state: &mut BTreeMap<String, u8>,
        stack: &mut Vec<String>,
        found: &mut Vec<String>,
    ) {
        state.insert(node.to_string(), 1);
        stack.push(node.to_string());
        for next in graph.get(node).into_iter().flatten() {
            match state.get(next.as_str()).copied().unwrap_or(0) {
                1 => {
                    let at = stack.iter().position(|m| m == next).unwrap_or(0);
                    let mut cycle = stack[at..].to_vec();
                    cycle.push(next.clone());
                    found.push(cycle.join(" -> "));
                }
                0 => walk(next, graph, state, stack, found),
                _ => {}
            }
        }
        stack.pop();
        state.insert(node.to_string(), 2);
    }

    for node in graph.keys() {
        if state.get(node.as_str()).copied().unwrap_or(0) == 0 {
            walk(node, &graph, &mut state, &mut Vec::new(), &mut found);
        }
    }

    assert!(
        found.is_empty(),
        "the module graph must stay acyclic, but found:\n  {}",
        found.join("\n  ")
    );
}
