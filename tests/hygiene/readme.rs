// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Every example in the README is one the compiler has seen
//!
//! `README.md` is what a stranger reads first, and nothing compiles it. Its
//! three examples were correct when this was written and would have gone on
//! looking correct through any rename, because the only thing holding them to
//! the API was somebody remembering.
//!
//! `#![doc = include_str!("../README.md")]` is the usual answer and is the wrong
//! one here: it would splice the badges, the headings and the whole document
//! into the crate documentation beside `lib.rs`'s own, which is written for that
//! job and says something different.
//!
//! So the README carries the *same text* as a doctest instead, and this checks
//! that it still does. The doctest is what rustdoc compiles; this is what stops
//! the copy in the README drifting away from it.
//!
//! ## What is compared
//!
//! A doctest's hidden lines — the `# ` scaffolding that makes an example
//! compile without showing a reader an async wrapper they did not ask about —
//! are dropped first. What is left is what the doctest displays, and that is
//! what the README has to match.

use std::fs;
use std::path::{Path, PathBuf};

/// The files whose doc comments may hold a README example.
const SOURCES: &[&str] = &["src"];

/// The visible lines of every fenced block in a doc comment under `dir`.
fn doctests(dir: &Path, into: &mut Vec<Vec<String>>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            doctests(&path, into);
            continue;
        }
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }

        let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let mut block: Option<Vec<String>> = None;

        for line in text.lines() {
            let trimmed = line.trim_start();
            let Some(rest) = trimmed
                .strip_prefix("///")
                .or_else(|| trimmed.strip_prefix("//!"))
            else {
                if let Some(open) = block.take() {
                    into.push(open);
                }
                continue;
            };
            let rest = rest.strip_prefix(' ').unwrap_or(rest);

            if rest.starts_with("```") {
                match block.take() {
                    Some(open) => into.push(open),
                    None => block = Some(Vec::new()),
                }
                continue;
            }

            // A hidden line is scaffolding the reader is not shown, so it is not
            // something the README could carry.
            if let Some(open) = block.as_mut()
                && rest != "#"
                && !rest.starts_with("# ")
            {
                open.push(rest.to_string());
            }
        }
    }
}

/// Every `rust` block in the README, in the order it appears.
fn readme_examples() -> Vec<Vec<String>> {
    let readme = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("README.md");
    let text = fs::read_to_string(&readme).expect("the README is in the repository");

    let mut out = Vec::new();
    let mut block: Option<Vec<String>> = None;

    for line in text.lines() {
        if line.starts_with("```rust") {
            block = Some(Vec::new());
            continue;
        }
        if line.starts_with("```") && block.is_some() {
            out.push(block.take().expect("a block was open"));
            continue;
        }
        if let Some(open) = block.as_mut() {
            open.push(line.to_string());
        }
    }

    out
}

/// The README's examples are the doctests' visible text, so rustdoc compiles
/// what a stranger reads.
///
/// A rename that misses the README fails here, which is the whole point: the
/// alternative is prose that goes on describing an API the crate no longer has.
#[test]
fn every_readme_example_is_a_doctest() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut compiled = Vec::new();
    for source in SOURCES {
        doctests(&root.join(source), &mut compiled);
    }

    let examples = readme_examples();
    assert!(
        !examples.is_empty(),
        "the README has stopped carrying examples"
    );

    for example in &examples {
        assert!(
            compiled.contains(example),
            "this README example is not the visible text of any doctest, so \
             nothing compiles it:\n\n{}\n",
            example.join("\n")
        );
    }
}
