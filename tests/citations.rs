// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Every cited file exists
//!
//! This crate's commenting style rests on a reader being able to find the
//! reasoning. A citation is a promise that the reasoning is somewhere, and by
//! 2026-08 twenty of them pointed at four files that were not in the repository:
//! two deleted with the references left behind, two never tracked at all. Four
//! were load-bearing, cited as the record of the defect a test exists to cover.
//!
//! An unkeepable citation is worse than none, because a reader spends time
//! looking. This is the check that stops the next one.
//!
//! ## What counts
//!
//! A backticked path carrying a directory and ending in `.md` or `.rs`. That
//! covers both kinds this repository has lost: documents deleted with the
//! references left behind, and source files cited as the evidence for a number.
//!
//! The second kind arrived on 2026-08-30, when `benches/` was removed and
//! thirteen doc comments went on pointing at the instruments that had measured
//! their constants. The numbers were kept and the pointers dropped, which is the
//! right trade, and this check is what makes the next one fail loudly rather
//! than rot quietly.
//!
//! Two things are deliberately out of scope. A URL is somebody else's promise
//! and cannot be checked from here. A path inside a fenced code block or a
//! shell line is usually an example rather than a claim.

use std::fs;
use std::path::{Path, PathBuf};

/// The trees whose comments are read.
const ROOTS: &[&str] = &["src", "tests", "examples", ".github", "build.rs", "assets"];

/// A cited path, and where it was cited from.
#[derive(Debug)]
struct Citation {
    /// The file doing the citing.
    from: PathBuf,
    /// Its 1-based line.
    line: usize,
    /// The path it named.
    target: String,
}

/// Every backticked Markdown path in `text`, with the line it sits on.
///
/// Hand-written rather than a regex: the crate has one regex engine for
/// signatures and one for patterns, and a test binary is not the place to make
/// a caller of either.
fn citations_in(path: &Path, text: &str) -> Vec<Citation> {
    let mut found = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let mut rest = line;
        while let Some(open) = rest.find('`') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('`') else { break };
            let quoted = &after[..close];
            rest = &after[close + 1..];

            if !quoted.ends_with(".md") && !quoted.ends_with(".rs") {
                continue;
            }
            // A citation names a directory this repository owns. Anything else
            // is prose about a file in general, or somebody else's repository.
            if !quoted.contains('/') {
                continue;
            }
            found.push(Citation {
                from: path.to_path_buf(),
                line: index + 1,
                target: quoted.to_string(),
            });
        }
    }
    found
}

/// Every file under `dir` worth reading, recursively.
fn sources(dir: &Path, into: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            sources(&path, into);
        } else if path
            .extension()
            .is_some_and(|e| e == "rs" || e == "yml" || e == "yaml" || e == "md")
        {
            into.push(path);
        }
    }
}

/// A citation is a promise that the reasoning is somewhere. This is the check
/// that it is.
#[test]
fn every_cited_document_is_in_the_repository() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    let mut files = Vec::new();
    for entry in ROOTS {
        let path = root.join(entry);
        if path.is_dir() {
            sources(&path, &mut files);
        } else if path.is_file() {
            files.push(path);
        }
    }
    assert!(
        !files.is_empty(),
        "no sources were read, so nothing is checked"
    );

    let mut dangling = Vec::new();
    for file in &files {
        let Ok(text) = fs::read_to_string(file) else {
            continue;
        };
        // A citation resolves against the repository root, or against the
        // directory of the file doing the citing. `tests/README.md` naming
        // `common/mod.rs` means the one beside it, and is not wrong for saying
        // so the way a reader of that file would.
        let beside = file.parent().unwrap_or(root);
        for citation in citations_in(file, &text) {
            let anywhere =
                root.join(&citation.target).exists() || beside.join(&citation.target).exists();
            if !anywhere {
                dangling.push(citation);
            }
        }
    }

    assert!(
        dangling.is_empty(),
        "{} citation(s) point at a document that is not here:\n{}",
        dangling.len(),
        dangling
            .iter()
            .map(|c| format!(
                "  {}:{} cites `{}`",
                c.from.strip_prefix(root).unwrap_or(&c.from).display(),
                c.line,
                c.target
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
