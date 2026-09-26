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

/// The modules a strategy is built from, which the crate keeps to itself.
///
/// Each holds state whose shape is still moving: the retry ledger, the adaptive
/// deadline, the congestion window, the tally a raw scan keeps of itself, the
/// loop the raw port scanners share. Publishing any of them would make that
/// shape a promise to every front end, and a caller driving a strategy needs
/// none of it: the strategy's constructor takes the settings that tune it.
const INTERNAL: &[&str] = &[
    "zond_engine::scanner::audit",
    "zond_engine::scanner::pacing",
    "zond_engine::scanner::payload",
    "zond_engine::scanner::pool",
    "zond_engine::scanner::strategy::frames",
    "zond_engine::scanner::strategy::icmp_error",
    "zond_engine::scanner::strategy::raw",
    "zond_engine::scanner::strategy::sweep",
    "zond_engine::scanner::strategy::ports::RawPortScan",
    "zond_engine::scanner::strategy::ports::RawProbeScan",
];

/// Making one of these public again is a deliberate act with a cost, and this
/// is where it has to be argued: a line in the listing under any of them fails
/// here before it reaches a release.
#[test]
fn the_machinery_a_strategy_is_built_from_stays_internal() {
    let listing = listing();
    let exposed: Vec<&str> = listing
        .lines()
        .filter(|line| {
            INTERNAL.iter().any(|path| {
                line.match_indices(path).any(|(at, _)| {
                    !line[at + path.len()..].starts_with(|c: char| c.is_alphanumeric() || c == '_')
                })
            })
        })
        .collect();
    assert!(
        exposed.is_empty(),
        "internal machinery in the public API: {exposed:#?}"
    );
}
