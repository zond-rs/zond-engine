// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The documentation standard, where the compiler cannot see it
//!
//! `#![warn(missing_docs)]` covers the public surface and CI denies it, so a
//! `pub` item without a doc comment fails the build already. Nothing covers the
//! rest, and in August 2026 an audit of `src/scanner/` found six doc blocks
//! that had been spliced onto a neighbouring item, leaving six items bare:
//!
//! | item | where its documentation had gone |
//! |---|---|
//! | `spawn_discovery` | its own summary line, repeated three times on one line |
//! | `FailureLog` | prepended to `UnroutableLog` |
//! | `pacing_for` | prepended to `rate_or` |
//! | `run_active_os_probe` | prepended to `run_traceroute` |
//! | `push_single` | prepended to `routable` |
//! | `probe_distance` | two stale summaries, neither its own |
//!
//! Every one was private, `pub(crate)` or `pub(super)`, so `missing_docs` could
//! not see any of them, and every one was syntactically valid, so `cargo doc`
//! rendered them without complaint. They arrived in different commits, which is
//! what makes this a gate rather than a one-off repair: it is something that
//! happens during ordinary editing.
//!
//! ## What is checked, and what deliberately is not
//!
//! Two rules, both crisp, because a heuristic that guesses at "this reads like
//! a summary for a different item" would fail on prose this module is full of.
//!
//! - **No `///` line carries a second `///`.** That is the shape a duplicated
//!   line takes and it has no legitimate form outside a code fence, which is
//!   excluded.
//! - **Every module-level item, and every `pub(crate)` or `pub(super)` item at
//!   any depth, carries a doc comment.** This extends the crate's existing
//!   standard exactly one visibility level down, which is where all six hid.
//!
//! A method inside an inherent `impl` is **not** checked. `FailureLog::push`,
//! `SweptLinks::drain` and their neighbours are one-line accessors on types
//! whose own documentation already says what they hold, and requiring a comment
//! on each would produce the restated-signature noise `CONTRIBUTING.md` rules
//! out.
//!
//! Five of the six above are caught without it, each confirmed by planting the
//! corruption back and watching this fail. The sixth, `probe_distance`, is an
//! inherent method and is the price of that exclusion.
//!
//! Scoped to `src/scanner/` because that is the tree the standard has been
//! brought up to. Widening it means documenting what the wider scan reports,
//! and the list is in the audit.

use std::fs;
use std::path::{Path, PathBuf};

/// The tree this standard is enforced over.
const SCOPE: &str = "src/scanner";

/// The module root of that tree, which lives beside it rather than inside it.
const SCOPE_ROOT: &str = "src/scanner.rs";

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("the source tree is readable") {
        let path = entry.expect("a readable entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The files in scope, sorted so a failure names them in a stable order.
fn sources() -> Vec<PathBuf> {
    let mut files = vec![PathBuf::from(SCOPE_ROOT)];
    rust_files(Path::new(SCOPE), &mut files);
    files.sort();
    files
}

/// `text` up to its test module, since test items are held to a different
/// standard and are documented by their own names.
fn production(text: &str) -> &str {
    text.find("\n#[cfg(test)]\nmod tests")
        .or_else(|| text.find("\n#[cfg(test)]\npub(crate) mod tests"))
        .map_or(text, |at| &text[..at])
}

/// Whether `line` declares an item this standard covers, given how deep it sits
/// and whether an inherent `impl` block encloses it.
///
/// Module level is column zero. A restricted-visibility item counts wherever it
/// is, which is what reaches `pub(super)` helpers declared inside a block.
fn covered_item(line: &str) -> bool {
    let trimmed = line.trim_start();
    let indented = line.len() != trimmed.len();

    let restricted = trimmed.starts_with("pub(crate)") || trimmed.starts_with("pub(super)");
    if indented && !restricted {
        return false;
    }

    // Stripped one prefix at a time and in order, because a chain of
    // `strip_prefix(..).or_else(..).map_or(..)` reads as though it does this and
    // does not: the `map_or` fallback hands back the string as it was before the
    // *previous* strip, so `pub(super) async fn` kept its `async ` and the item
    // went unchecked. Which is the class of thing this file exists to catch.
    let mut rest = trimmed;
    for prefix in ["pub(crate)", "pub(super)", "pub"] {
        if let Some(stripped) = rest.strip_prefix(prefix) {
            rest = stripped.trim_start();
            break;
        }
    }
    for prefix in ["default ", "async ", "unsafe ", "extern ", "const "] {
        if let Some(stripped) = rest.strip_prefix(prefix) {
            rest = stripped.trim_start();
        }
    }

    // `mod foo;` is deliberately absent. A module's documentation is the `//!`
    // block at the top of its own file, which `missing_docs` already reads, and
    // the declarations in `scanner.rs` are grouped under `//` comments covering
    // several at once rather than one each.
    [
        "fn ", "struct ", "enum ", "trait ", "type ", "const ", "static ",
    ]
    .iter()
    .any(|keyword| rest.starts_with(keyword))
}

/// A duplicated `///` on one line is what the triplication looked like, and it
/// has no legitimate form: a doc comment showing Rust code that itself carries
/// doc comments puts them on their own lines inside the fence.
#[test]
fn no_doc_line_carries_a_second_doc_marker() {
    let mut offenders = Vec::new();

    for path in sources() {
        let text = fs::read_to_string(&path).expect("a readable source file");
        for (number, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if (trimmed.starts_with("///") || trimmed.starts_with("//!"))
                && trimmed.matches("///").count() > 1
            {
                offenders.push(format!("{}:{}", path.display(), number + 1));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "a doc line carries a second `///`, which is how a duplicated line reads:\n  {}",
        offenders.join("\n  ")
    );
}

/// The gate the six corruptions would have tripped. An item whose documentation
/// was taken away by a neighbour is an item with no documentation, and that is
/// the thing to look for: the merged block itself is prose, and no rule about
/// prose is worth the false positives.
#[test]
fn every_item_the_standard_covers_is_documented() {
    let mut bare = Vec::new();

    for path in sources() {
        let text = fs::read_to_string(&path).expect("a readable source file");
        let lines: Vec<&str> = production(&text).lines().collect();

        // Whether an inherent `impl` encloses the current line. A trait impl's
        // methods inherit their documentation from the trait, and an inherent
        // impl's one-line accessors are held to the module's own judgement.
        let mut in_impl = false;

        for (index, line) in lines.iter().enumerate() {
            if line.starts_with("impl") {
                in_impl = true;
                continue;
            }
            if in_impl && *line == "}" {
                in_impl = false;
                continue;
            }
            if in_impl || !covered_item(line) {
                continue;
            }

            // Attributes sit between the doc comment and the item.
            let mut above = index;
            while above > 0 {
                let previous = lines[above - 1].trim_start();
                if previous.starts_with("#[") || previous.starts_with("#!") {
                    above -= 1;
                } else {
                    break;
                }
            }

            if above == 0 || !lines[above - 1].trim_start().starts_with("///") {
                bare.push(format!("{}:{}: {}", path.display(), index + 1, line.trim()));
            }
        }
    }

    assert!(
        bare.is_empty(),
        "an item this standard covers has no doc comment, which is what a doc \
         block spliced onto its neighbour leaves behind:\n  {}",
        bare.join("\n  ")
    );
}
