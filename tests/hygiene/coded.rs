// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Every public error has a code
//!
//! `Coded` promises a stable name for every error this crate hands a caller,
//! and a promise kept by remembering breaks at the first error somebody adds
//! and does not think of. So it is checked against the one list of what the
//! crate hands out: `public-api.txt`, which the release checks hold to the
//! build. Every type there that implements `std::error::Error` has to
//! implement `Coded` beside it.

use std::collections::BTreeSet;
use std::path::Path;

/// The types a line of the public API listing implements `trait_path` for.
fn implementors<'a>(listing: &'a str, trait_path: &str) -> BTreeSet<&'a str> {
    let prefix = format!("impl {trait_path} for ");
    listing
        .lines()
        .filter_map(|line| line.strip_prefix(prefix.as_str()))
        .collect()
}

/// A caller outside Rust branches on the code, so an error without one is a
/// failure it can only report by its wording, which is free to change.
#[test]
fn every_public_error_carries_a_code() {
    let listing =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("public-api.txt"))
            .expect("public-api.txt is in the repository");

    let errors = implementors(&listing, "core::error::Error");
    let coded = implementors(&listing, "zond_engine::error::Coded");
    assert!(
        errors.len() > 10,
        "the listing names the crate's errors: found {}",
        errors.len()
    );

    let uncoded: Vec<&str> = errors.difference(&coded).copied().collect();
    assert!(
        uncoded.is_empty(),
        "public errors with no stable code: {uncoded:#?}"
    );
}
