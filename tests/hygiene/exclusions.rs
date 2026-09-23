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
//! Both were broken, within two targets of each other, by paths added after the
//! module was written and unknown to it:
//!
//! - **The resume path.** `restore_hosts` wrote hosts into the store through
//!   neither gate. A scan interrupted before an exclusion was added brought the
//!   forbidden addresses back with it.
//! - **The neighbour table.** `seed_from_neighbor_table` took candidates from
//!   the host's own neighbour table into the target set *after* withholding. A
//!   swept segment sent a unicast solicitation to an address somebody had been
//!   told would not be probed — and because the recording gate still dropped
//!   the finding, the report stayed clean and the packet was invisible.
//!
//! Before those fixes, `exclusions.excludes()` was called in **one** production
//! place in the whole crate. The rule lived in one module and was kept by every
//! caller remembering it.
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
//! **The sending promise is not.** The neighbour-table path did not go near the
//! store; it put an address into a target set, and there is no honest grep for
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
     edit attached once it has, and every finding in the engine goes through it. \
     `restore_hosts` is the resume path and holds every address a restored host \
     carries to the same set before seeding what an earlier sitting found, since \
     nothing it restores passes through `write_host`.",
)];

/// The methods that put a host into the store.
const WRITES: &[&str] = &["store.insert", "store.get_mut", "store.entry"];

/// The files belonging to a module some parent declared `#[cfg(test)]`.
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
            if line.trim() != "#[cfg(test)]" {
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

/// `text` with `#[cfg(test)]` items removed. A fixture seeding a store says
/// nothing about how the engine writes one.
fn without_tests(text: &str) -> String {
    let mut kept = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(at) = rest.find("#[cfg(test)]") {
        kept.push_str(&rest[..at]);
        let after = &rest[at..];
        let Some(open) = after.find('{') else {
            break;
        };
        let mut depth = 0usize;
        let mut end = None;
        for (offset, byte) in after[open..].bytes().enumerate() {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open + offset + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        match end {
            Some(end) => rest = &after[end..],
            None => break,
        }
    }
    kept.push_str(rest);
    kept
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

/// Nobody explains themselves in a blank line.
#[test]
fn every_store_writer_says_something() {
    for (path, how) in STORE_WRITERS {
        assert!(
            how.len() > 60,
            "{path}'s note is too short to be an answer: {how:?}"
        );
    }
}
