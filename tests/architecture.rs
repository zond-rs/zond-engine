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
/// **This is the enforced list.** The layout section of `src/lib.rs` states the
/// same rule for a reader arriving at the documentation and groups the modules
/// for reading rather than for the rule, so the two are not line for line the
/// same and only this one decides anything.
const ORDER: &[&str] = &[
    "format",
    "logging",
    "model",
    "version",
    "protocols",
    "system",
    "transport",
    "evasion",
    "config",
    // Above `config` because a fingerprinter is told how far to go by
    // `ServiceDetection`, and above `transport` because reading a stack off a
    // reply parses the segment the capture handed over. It was below both, and
    // the two edges went unseen for as long as this file read a third of some
    // files.
    "fingerprint",
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

/// The file's production source: every `#[cfg(test)]` item removed, and every
/// line comment blanked.
///
/// **Truncating at the first `#[cfg(test)]` was not the same thing**, and the
/// difference was most of the crate. Whole-file test modules are gated at the
/// declaration site, which is what that was written for; but a `#[cfg(test)] mod
/// corpus;` or a gated helper near the top of a file threw away everything below
/// it, and `src/protocols/tcp.rs` was checked to line 78 of 928. Across `src/`
/// it read 65% of the lines and reported nothing, while four real violations
/// stood — one of them a plain `use crate::config::…` sixty lines further down
/// than the cut.
///
/// Comments go because this file's own prose, and every intra-doc link like
/// `[`Redaction`](crate::export::Redaction)`, names modules without depending on
/// them.
fn production_source(text: &str) -> String {
    strip_comments(&strip_test_items(text))
}

/// Removes each `#[cfg(test)]` or `#[cfg(all(test, …))]` item whole, by matching
/// the braces of the item it is attached to.
fn strip_test_items(text: &str) -> String {
    const GATES: [&str; 2] = ["#[cfg(test)]", "#[cfg(all(test"];

    let mut out = String::with_capacity(text.len());
    let mut rest = text;

    loop {
        let Some(at) = GATES.iter().filter_map(|gate| rest.find(gate)).min() else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&rest[..at]);

        // Past the attribute, by its own brackets, so `#[cfg(all(test, unix))]`
        // ends where it ends rather than at the first `]`.
        let after_attribute = balanced(&rest[at..], '[', ']').unwrap_or(rest.len() - at);
        let item = &rest[at + after_attribute..];

        // Then the item: a declaration up to its `;`, or a body in braces.
        let ends = match item.find(['{', ';']) {
            Some(i) if item.as_bytes()[i] == b';' => i + 1,
            Some(i) => i + balanced(&item[i..], '{', '}').unwrap_or(item.len() - i),
            None => item.len(),
        };
        rest = &item[ends..];
    }
}

/// How far into `text` the group opened by its first `open` is closed, or `None`
/// where it never is.
fn balanced(text: &str, open: char, close: char) -> Option<usize> {
    let mut depth = 0usize;
    for (i, c) in text.char_indices() {
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return Some(i + c.len_utf8());
            }
        }
    }
    None
}

/// Blanks `//` comments, keeping the lines so nothing else shifts.
fn strip_comments(text: &str) -> String {
    text.lines()
        .map(|line| match line.find("//") {
            Some(at) => &line[..at],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
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
        let source = production_source(&text);

        // **Every `crate::`, not only the ones a `use` line opens with.** A
        // `pub use crate::…` is a dependency, a second name inside one set of
        // braces is a dependency, and an inline `crate::export::schema::name(..)`
        // in the middle of an expression is a dependency that no amount of
        // reading `use` lines will ever see. Three of the four violations this
        // file missed were of the last kind.
        for at in source.match_indices("crate::").map(|(i, _)| i) {
            let before = source[..at].chars().next_back();
            if before.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == ':') {
                continue;
            }
            for imported in modules_named(&source[at + "crate::".len()..]) {
                if imported != owner && known.contains(imported.as_str()) {
                    graph.entry(owner.clone()).or_default().insert(imported);
                }
            }
        }
    }
    graph
}

/// The module names a path fragment after `crate::` reaches for.
///
/// One name for an ordinary path, and one per member for a set: `{model::Host,
/// config::ZondConfig}` names two modules and reading only the first would miss
/// the second.
fn modules_named(text: &str) -> Vec<String> {
    let text = text.trim_start();
    if !text.starts_with('{') {
        let name: String = text
            .chars()
            .take_while(|c| c.is_ascii_lowercase() || *c == '_')
            .collect();
        return if name.is_empty() {
            Vec::new()
        } else {
            vec![name]
        };
    }

    let Some(end) = balanced(text, '{', '}') else {
        return Vec::new();
    };

    let mut names = Vec::new();
    let mut depth = 0usize;
    let mut member = String::new();
    for c in text[1..end - 1].chars() {
        match c {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                names.extend(modules_named(&member));
                member.clear();
                continue;
            }
            _ => {}
        }
        member.push(c);
    }
    names.extend(modules_named(&member));
    names
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
