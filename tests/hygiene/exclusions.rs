// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The exclusion policy's recording promise, as a census
//!
//! [`Exclusions`] promises two things, and its own documentation says which code
//! keeps each:
//!
//! | promise | kept at |
//! |---|---|
//! | no probe is *addressed* to an excluded address | `withhold` / `withhold_targets`, before anything is opened; `ScanContext::may_probe`, for an address a strategy learns while it runs |
//! | no excluded address appears in the report | `ScanContext::write_host`, on every finding |
//!
//! Either is broken by a path added after the module was written and unknown
//! to it, and two such paths show how:
//!
//! - **The resume path.** `restore_hosts` writes hosts into the store. Through
//!   neither gate, a scan interrupted before an exclusion was added would bring
//!   the forbidden addresses back with it.
//! - **The neighbour table.** `seed_from_neighbor_table` takes candidates from
//!   the host's own neighbour table into the target set. Taken in *after*
//!   withholding, a swept segment would send a unicast solicitation to an
//!   address somebody had been told would not be probed — and because the
//!   recording gate still drops the finding, the report would stay clean and
//!   the packet invisible.
//!
//! Left to itself, the rule lives in one module and is kept by every caller
//! remembering it.
//!
//! ## Why a census here, and an invariant in the portable tier
//!
//! [`attribution.rs`](attribution.rs) answers a similar problem with a census,
//! because "reads an ICMP error" is a thing a grep can see. Only one of the two
//! promises here is like that.
//!
//! **The recording promise is lexical.** Everything that can put a host in the
//! report goes through the store, and a write to the store is `store.insert`,
//! `store.get_mut` or `store.entry`. So it gets a census, in the same shape:
//! every production writer is listed with how it is held to the policy, and a
//! new one fails the test until somebody writes that line. This module is that
//! census.
//!
//! **The sending promise is not.** The neighbour-table path does not go near the
//! store; it puts an address into a target set, and there is no honest grep for
//! "this address will be probed". So it gets the stronger thing instead: an
//! invariant over what a plan actually contains, which has to build a plan
//! through the library and so lives in `tests/portable/exclusions.rs`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// How a write into the host store reaches the store, and what holds it to the
/// exclusions.
///
/// **Adding a file here is the point of this census.** If new code writes a
/// host, say on this line what stops it writing one the operator forbade — and
/// if the answer is "nothing", that is a finding rather than an entry.
const STORE_WRITERS: &[(&str, &str)] = &[(
    "src/scanner/session.rs",
    "two writers, both gated. `write_host` is the gate itself: it refuses an \
     excluded key before the caller's edit runs and every excluded address the \
     edit attached once it has, withholding an excluded router on the host's \
     path and an excluded middlebox that sent evidence about it, and every \
     finding in the engine goes through it. \
     `restore_hosts` is the resume path and holds every address a restored host \
     carries to the same set before seeding what an earlier sitting found, since \
     nothing it restores passes through `write_host`.",
)];

/// The methods that put a host into the store.
const WRITES: &[&str] = &["store.insert", "store.get_mut", "store.entry"];

/// Who attaches a sender's address to a port's discovery record, and why that
/// cannot put an excluded address in the report.
///
/// A second census, for the one address a host's record can carry that
/// `write_host` does not hold to the policy: `Discovery::source_ip`, which
/// names the reply's sender, the source address its IP header carried. A
/// sender is often not the target, and a router or firewall answering for a
/// filtered port can sit at an address the operator excluded. It is not held
/// at `write_host` because holding it would cost a walk of every port on every
/// finding, on the path every port scan takes, for a field no scanner fills.
/// What keeps the promise instead is that no scanner fills it, and this list
/// is where a scanner that starts to has to say how it withholds an excluded
/// sender first: the way `EvidenceSource` does for a host's evidence, keeping
/// the verdict, marking it second-hand, and naming nobody.
const DISCOVERY_SOURCE_WRITERS: &[(&str, &str)] = &[(
    "src/record.rs",
    "reads a port's discovery back from a journal or an imported report, and \
     carries only what a scan already recorded. No scan records a source, since \
     no scanner is in this list, so a journal holds none to bring back; an \
     imported report is the other scan's document and not a scan at all.",
)];

/// The call that names a port's sender, the source address of the reply that
/// settled it.
const DISCOVERY_SOURCE: &str = ".with_source_ip(";

/// The files belonging to a module some parent compiles only for a test.
///
/// `without_tests` strips a `#[cfg(test)] mod tests { … }` written *inside* a
/// file. It cannot see `#[cfg(test)] pub(crate) mod fixture;` in the parent,
/// which makes a whole file test-only — and `src/export/fixture.rs` is exactly that,
/// so without this the census reports a fixture as an ungated writer.
fn test_only_modules() -> BTreeSet<PathBuf> {
    let mut out = BTreeSet::new();
    for path in every_source() {
        let text = fs::read_to_string(&path).expect("a source file is readable");
        for (index, line) in text.lines().enumerate() {
            let condition = line
                .trim()
                .strip_prefix("#[cfg(")
                .and_then(|rest| rest.strip_suffix(")]"));
            if !condition.is_some_and(implies_test) {
                continue;
            }
            let Some(next) = text.lines().nth(index + 1) else {
                continue;
            };
            let next = next.trim().trim_end_matches(';');
            let Some(name) = next.split_whitespace().last() else {
                continue;
            };
            if !next.contains("mod ") || !next.ends_with(name) || next.contains('{') {
                continue;
            }

            // `src/export.rs` declaring `mod fixture;` means `src/export/fixture.rs`.
            let dir = match path.file_stem().and_then(|s| s.to_str()) {
                Some("lib") | Some("mod") => path.parent().expect("a parent").to_path_buf(),
                Some(stem) => path.parent().expect("a parent").join(stem),
                None => continue,
            };
            out.insert(dir.join(format!("{name}.rs")));
            out.insert(dir.join(name).join("mod.rs"));
        }
    }
    out
}

fn every_source() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let mut entries: Vec<_> = fs::read_dir(dir)
            .expect("src is readable")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(Path::new("src"), &mut out);
    out
}

/// The files whose contents describe how the engine behaves, which is every
/// source that is not compiled only for a test.
fn sources() -> Vec<PathBuf> {
    let test_only = test_only_modules();
    every_source()
        .into_iter()
        .filter(|path| !test_only.contains(path))
        .collect()
}

/// `text` with the items compiled only for a test removed. A fixture seeding a
/// store says nothing about how the engine writes one.
fn without_tests(text: &str) -> String {
    let mut kept = String::with_capacity(text.len());
    let mut rest = text;

    while let Some((at, attribute_end)) = next_test_only_attribute(rest) {
        kept.push_str(&rest[..at]);
        rest = &rest[attribute_end..];
        rest = &rest[item_len(rest)..];
    }
    kept.push_str(rest);
    kept
}

/// Where the next `#[cfg(…)]` whose condition implies [`implies_test`] starts
/// in `text`, and where the attribute ends.
fn next_test_only_attribute(text: &str) -> Option<(usize, usize)> {
    let mut from = 0;
    while let Some(found) = text[from..].find("#[cfg(") {
        let at = from + found;
        let condition = at + "#[cfg(".len();
        let close = condition + closing_paren(&text[condition..])?;
        if text[close + 1..].starts_with(']') && implies_test(&text[condition..close]) {
            return Some((at, close + 2));
        }
        from = condition;
    }
    None
}

/// The offset of the `)` closing a parenthesis opened just before `text`.
fn closing_paren(text: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, byte) in text.bytes().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' if depth == 0 => return Some(offset),
            b')' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// Whether a `cfg` condition holds only when compiling a test: `test` itself,
/// an `all` with such a term, or an `any` made only of them. `not(test)` names
/// the word and is the opposite, and `any(test, feature = "…")` also compiles
/// into a build that enables the feature, so neither counts.
fn implies_test(condition: &str) -> bool {
    let condition = condition.trim();
    if condition == "test" {
        return true;
    }
    let terms = |name: &str| {
        condition
            .strip_prefix(name)
            .and_then(|rest| rest.trim_start().strip_prefix('('))
            .and_then(|rest| rest.strip_suffix(')'))
            .map(top_level_terms)
    };
    if let Some(terms) = terms("all") {
        return terms.iter().any(|term| implies_test(term));
    }
    if let Some(terms) = terms("any") {
        return !terms.is_empty() && terms.iter().all(|term| implies_test(term));
    }
    false
}

/// The comma-separated terms of a condition list, split only at its own level.
fn top_level_terms(list: &str) -> Vec<&str> {
    let mut terms = Vec::new();
    let (mut depth, mut start) = (0usize, 0);
    for (offset, byte) in list.bytes().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                terms.push(&list[start..offset]);
                start = offset + 1;
            }
            _ => {}
        }
    }
    terms.push(&list[start..]);
    terms.retain(|term| !term.trim().is_empty());
    terms
}

/// How many bytes of `text` the item it starts with takes up, attributes
/// included: through the `}` closing its body, or through the `;` or `,`
/// ending an item that has none (`mod fixture;`, a field, a variant), or up
/// to the `}` closing whatever holds it. Lexical, like the rest of this
/// census: brackets inside a string literal are counted as code.
fn item_len(text: &str) -> usize {
    let mut depth = 0usize;
    for (offset, byte) in text.bytes().enumerate() {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' if depth == 0 => return offset,
            b'}' if depth == 1 => return offset + 1,
            b')' | b']' | b'}' => depth -= 1,
            b';' | b',' if depth == 0 => return offset + 1,
            _ => {}
        }
    }
    text.len()
}

/// **Every path that can put a host in the report is one somebody has held to
/// the exclusions.**
#[test]
fn every_writer_into_the_host_store_has_said_how_it_is_gated() {
    let mut found = BTreeSet::new();
    for path in sources() {
        let text = fs::read_to_string(&path).expect("a source file is readable");
        let production = without_tests(&text);
        if WRITES.iter().any(|write| production.contains(write)) {
            found.insert(path.to_string_lossy().replace('\\', "/"));
        }
    }

    let listed: BTreeSet<String> = STORE_WRITERS
        .iter()
        .map(|(path, _)| (*path).to_string())
        .collect();

    let unlisted: Vec<&String> = found.difference(&listed).collect();
    assert!(
        unlisted.is_empty(),
        "these write into the host store and are not in STORE_WRITERS: {unlisted:?}\n\n\
         `Exclusions` promises that no excluded address appears in the report, and keeps \
         that promise at `write_host`. A write that goes round it is a host the operator \
         forbade, reported anyway, which is how the resume path once did it.\n\n\
         Route the write through `ScanContext::write_host`, or check `exclusions` yourself \
         and add the file to STORE_WRITERS in tests/hygiene/exclusions.rs saying so."
    );

    let stale: Vec<&String> = listed.difference(&found).collect();
    assert!(
        stale.is_empty(),
        "these are in STORE_WRITERS but no longer write into the store: {stale:?}\n\n\
         Remove them, so the list stays a census rather than a wish."
    );
}

/// **Nothing a scan records names a port's sender without saying how an
/// excluded one is kept out of the report.**
///
/// The recording gate withholds an excluded router on a host's path and an
/// excluded middlebox behind a host's evidence, and leaves the sender a port's
/// discovery names alone for the cost [`DISCOVERY_SOURCE_WRITERS`] gives. That
/// holds only while nothing fills the field, so the first scanner to fill it
/// has to stop here and decide how its excluded senders are withheld.
#[test]
fn every_writer_of_a_ports_sender_has_said_how_it_is_withheld() {
    let mut found = BTreeSet::new();
    for path in sources() {
        let text = fs::read_to_string(&path).expect("a source file is readable");
        if without_tests(&text).contains(DISCOVERY_SOURCE) {
            found.insert(path.to_string_lossy().replace('\\', "/"));
        }
    }

    let listed: BTreeSet<String> = DISCOVERY_SOURCE_WRITERS
        .iter()
        .map(|(path, _)| (*path).to_string())
        .collect();

    let unlisted: Vec<&String> = found.difference(&listed).collect();
    assert!(
        unlisted.is_empty(),
        "these name a port's sender and are not in DISCOVERY_SOURCE_WRITERS: {unlisted:?}\n\n\
         `write_host` does not withhold the source a port's discovery names, so a sender \
         the operator excluded would reach the report. Withhold an excluded sender before \
         recording it, the way `EvidenceSource::Withheld` withholds a status reason's, and \
         add the file to \
         DISCOVERY_SOURCE_WRITERS in tests/hygiene/exclusions.rs saying how."
    );

    let stale: Vec<&String> = listed.difference(&found).collect();
    assert!(
        stale.is_empty(),
        "these are in DISCOVERY_SOURCE_WRITERS but no longer name a port's sender: \
         {stale:?}\n\nRemove them, so the list stays a census rather than a wish."
    );
}

/// Nobody explains themselves in a blank line.
#[test]
fn every_store_writer_says_something() {
    for (path, how) in STORE_WRITERS.iter().chain(DISCOVERY_SOURCE_WRITERS) {
        assert!(
            how.len() > 60,
            "{path}'s note is too short to be an answer: {how:?}"
        );
    }
}

/// **Code compiled only under a test is left out of the census, whatever
/// spells the condition, and nothing else is.**
///
/// A fixture behind `#[cfg(all(test, unix))]` is as much test code as one
/// behind `#[cfg(test)]`, and counting it would list a fixture as an ungated
/// writer. The other way round is worse: a condition that merely names
/// `test` without implying it, or an item without a body, must not take the
/// production code after it out of the census with it.
#[test]
fn only_code_compiled_solely_for_tests_is_left_out() {
    let text = "\
fn production_one() { store.insert(1); }
#[cfg(all(test, unix))]
mod unix_tests { fn seed() { store.insert(2); } }
#[cfg(any(test, feature = \"test-support\"))]
fn support() { store.entry(3); }
#[cfg(not(test))]
fn release_only() { store.get_mut(4); }
#[cfg(test)]
mod fixture;
fn production_two() { store.insert(5); }
#[cfg(any(test, all(test, windows)))]
fn helper() { store.insert(6); }
";
    let kept = without_tests(text);
    for production in ["insert(1)", "entry(3)", "get_mut(4)", "insert(5)"] {
        assert!(
            kept.contains(production),
            "{production} was dropped:\n{kept}"
        );
    }
    for test_only in ["insert(2)", "insert(6)"] {
        assert!(!kept.contains(test_only), "{test_only} was kept:\n{kept}");
    }
}
