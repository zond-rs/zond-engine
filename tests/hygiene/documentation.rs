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
//! Scoped to the whole of `src`, which it was not until the September 2026 health
//! audit: it grew one module at a time as each was read, and `system/` alone had
//! four private modules with no module documentation at all, `routing.rs` among
//! them, which is the file every strategy a scan runs follows from. [`SCOPE`]
//! carries the two reasons it stopped short of `src` for as long as it did, and
//! what answered each.

use std::fs;
use std::path::{Path, PathBuf};

/// What this standard is enforced over: a directory covers itself and
/// everything under it, a file covers itself.
///
/// **The whole library.** It was not always: this was grown one audit at a time
/// as each module was brought up to the standard, and the note here used to give
/// two reasons for stopping short of `src`. Both are answered.
///
/// The first was that pointing it at `src` reported ninety items in modules
/// nobody had read, and documenting those means writing prose for code sight
/// unseen — the register `CONTRIBUTING.md` is dialling back. That was true and is
/// no longer: the September 2026 health audit read them and the sixty-eight real
/// ones now carry documentation. The largest run was the twenty-four `…Dto`
/// structs in `src/import/report/json.rs`, which are the read side of the
/// exported JSON contract and were the least documented thing in the crate.
///
/// The second was that it would be measuring the wrong thing, because several of
/// the ninety were `#[test]` functions in files gated at their `mod` declaration
/// rather than by an inner `mod tests`, which [`production`] cannot see from
/// inside the file. That one was a real defect in this gate and is fixed:
/// [`is_test_only`] reads the declaration.
const SCOPE: &[&str] = &["src"];

/// Whether `path` is a module the crate declares under `#[cfg(test)]`.
///
/// A file gated at its `mod` line — `#[cfg(test)] mod corpus;` — is test code
/// from its first byte, and nothing inside it says so. [`production`] strips an
/// inner `#[cfg(test)] mod tests`, which is the other convention, and cannot see
/// this one; before this, eleven test functions in five such files were reported
/// as undocumented production items, and *a rule that flags test code as
/// undocumented production code is a rule people learn to silence.*
///
/// Read from the declaration rather than kept as a list here, so a module gated
/// tomorrow is covered without this file moving.
fn is_test_only(path: &Path) -> bool {
    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return false;
    };
    let Some(dir) = path.parent() else {
        return false;
    };

    // A module file is declared either by the sibling .rs named for its
    // directory, or by a mod.rs inside that directory. Both are tried.
    let parents = [dir.join("mod.rs"), dir.with_extension("rs")];
    for parent in parents {
        let Ok(text) = fs::read_to_string(&parent) else {
            continue;
        };
        let declaration = format!("mod {stem};");
        let lines: Vec<&str> = text.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            if !line.contains(&declaration) {
                continue;
            }
            // The attribute sits directly above, or above a doc comment on it.
            let nearest = lines[index.saturating_sub(4)..index]
                .iter()
                .rfind(|l| !l.trim_start().starts_with("//"));
            if nearest.is_some_and(|l| {
                let trimmed = l.trim_start();
                trimmed.starts_with("#[cfg(test)]") || trimmed.starts_with("#[cfg(all(test")
            }) {
                return true;
            }
        }
    }
    false
}

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("the source tree is readable") {
        let path = entry.expect("a readable entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") && !is_test_only(&path) {
            out.push(path);
        }
    }
}

/// The files in scope, sorted so a failure names them in a stable order.
fn sources() -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in SCOPE {
        let path = Path::new(entry);
        if path.is_dir() {
            rust_files(path, &mut files);
        } else if !is_test_only(path) {
            files.push(path.to_path_buf());
        }
    }
    files.sort();
    files.dedup();
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

            // Attributes and ordinary `//` line comments sit between the doc
            // comment and the item: an `#[allow]` above the signature, or a `//`
            // note explaining a decision the doc block did not. Both are stepped
            // over to reach the `///`. A `///` or `//!` is not, so an item still has
            // to carry a doc comment of its own rather than borrow a neighbour's.
            //
            // **An attribute is not always one line.** `thiserror`'s `#[error(…)]`
            // routinely spans three or four, and a walk that only recognised a
            // line *starting* `#[` stopped at the closing `)]` and reported the
            // item as bare. `UnknownTechnique` is documented and was reported
            // anyway, which is a gate crying wolf — the failure mode that gets a
            // gate switched off. So the step counts brackets: a line that closes
            // more than it opens is the tail of an attribute, and the walk
            // continues through it until the depth is level again.
            let mut above = index;
            let mut depth: i32 = 0;
            while above > 0 {
                let previous = lines[above - 1].trim_start();
                let is_doc = previous.starts_with("///") || previous.starts_with("//!");
                let is_line_comment = previous.starts_with("//") && !is_doc;

                if depth > 0 {
                    // Inside a multi-line attribute: keep walking to its `#[`.
                    depth += previous.matches(']').count() as i32;
                    depth -= previous.matches('[').count() as i32;
                    above -= 1;
                    continue;
                }
                if is_doc {
                    break;
                }
                if is_line_comment {
                    above -= 1;
                    continue;
                }
                if previous.starts_with("#[") || previous.starts_with("#!") {
                    // One line if its brackets balance, otherwise the head of a
                    // block that has already been walked past.
                    above -= 1;
                    continue;
                }
                if previous.ends_with(']') {
                    depth =
                        previous.matches(']').count() as i32 - previous.matches('[').count() as i32;
                    if depth > 0 {
                        above -= 1;
                        continue;
                    }
                }
                break;
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
