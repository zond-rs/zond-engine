// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What the public surface may promise
//!
//! Every line of `public-api.txt` is a commitment: a name a front end may build
//! on, and so one this crate cannot change without a breaking release. The
//! rules here keep that list from promising more than the crate means to. Each
//! is checked against the listing rather than the source, because the listing
//! is what a caller actually sees, re-exports and all, and the release checks
//! already hold it to the build.

use std::path::Path;

/// The public API listing, as the release checks generate it.
fn listing() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("public-api.txt"))
        .expect("public-api.txt is in the repository")
}

/// A vocabulary's `ALL` exists so a caller can walk an enum it cannot match
/// exhaustively. As a fixed-size array its length would be part of its type,
/// and the variant `#[non_exhaustive]` makes additive would break every caller
/// that named that type: the same break, moved one line over.
#[test]
fn no_public_constant_is_an_array_of_the_crates_own_type() {
    let listing = listing();
    let arrays: Vec<&str> = listing
        .lines()
        .filter(|line| {
            line.starts_with("pub const ")
                && (line.contains(": [zond_engine::") || line.contains(": [Self;"))
        })
        .collect();
    assert!(
        arrays.is_empty(),
        "public constants whose length is part of their type: {arrays:#?}"
    );
    assert!(
        listing.contains("::port::Protocol::ALL: &'static [Self]"),
        "the listing still spells a slice constant the way this check reads it"
    );
}
